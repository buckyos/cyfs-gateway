use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::{
    create_process_chain_executor, get_external_commands, GlobalCollectionManagerRef,
    GlobalProcessChainsRef, JsExternalsManagerRef, ProcessChainConfigs, ServerManagerWeakRef,
};
use crate::ConfigResult;
use log::{debug, error, info};
use tokio::task::JoinHandle;
use tokio::time::{interval_at, Instant};

#[derive(Clone)]
pub struct TimerTaskConfig {
    pub id: String,
    pub timeout: u64,
    pub process_chains: ProcessChainConfigs,
}

pub struct TimerManager {
    tasks: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl TimerManager {
    pub fn new() -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
        }
    }

    pub fn stop_all(&self) {
        let mut tasks = self.tasks.lock().unwrap();
        for (_, task) in tasks.drain() {
            task.abort();
        }
    }

    pub async fn reload(
        &self,
        timers: &[TimerTaskConfig],
        server_manager: ServerManagerWeakRef,
        global_process_chains: GlobalProcessChainsRef,
        global_collection_manager: GlobalCollectionManagerRef,
        js_externals: JsExternalsManagerRef,
    ) -> ConfigResult<()> {
        self.stop_all();

        if timers.is_empty() {
            return Ok(());
        }

        let mut tasks = self.tasks.lock().unwrap();
        for timer in timers {
            let timer_id = timer.id.clone();
            let interval_secs = timer.timeout;
            let process_chains = timer.process_chains.clone();
            let server_manager = server_manager.clone();
            let global_process_chains = global_process_chains.clone();
            let global_collection_manager = global_collection_manager.clone();
            let js_externals = js_externals.clone();

            let task = tokio::task::spawn(async move {
                let external_commands = Some(get_external_commands(server_manager.clone()));
                let (executor, _) = match create_process_chain_executor(
                    &process_chains,
                    Some(global_process_chains),
                    Some(global_collection_manager),
                    external_commands,
                    Some(js_externals),
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "create process chain executor for timer {} failed: {}",
                            timer_id, e
                        );
                        return;
                    }
                };

                info!(
                    "timer {} started with interval {}s",
                    timer_id, interval_secs
                );
                let mut ticker = interval_at(
                    Instant::now() + Duration::from_secs(interval_secs),
                    Duration::from_secs(interval_secs),
                );
                loop {
                    ticker.tick().await;
                    let timer_executor = executor.fork();
                    match timer_executor.execute_lib().await {
                        Ok(ret) => {
                            debug!(
                                "timer {} execute done control={} value={:?}",
                                timer_id,
                                ret.is_control(),
                                ret.value()
                            );
                        }
                        Err(e) => {
                            error!("timer {} execute failed: {}", timer_id, e);
                        }
                    }
                }
            });

            tasks.insert(timer.id.clone(), task);
        }

        Ok(())
    }
}

impl Drop for TimerManager {
    fn drop(&mut self) {
        let mut tasks = self.tasks.lock().unwrap();
        for (_, task) in tasks.drain() {
            task.abort();
        }
    }
}
