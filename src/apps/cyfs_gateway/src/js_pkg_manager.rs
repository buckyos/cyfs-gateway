use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sfo_js::{Context, JsEngine, JsString, JsValue};
use sfo_js::object::builtins::JsArray;
pub use sfo_result::err as js_pkg_err;
pub use sfo_result::into_err as into_js_pkg_err;

pub type JsPkgResult<T> = sfo_result::Result<T, ()>;

#[derive(Deserialize)]
pub struct JsPkgConfig {
    name: String,
    main: Option<String>,
    description: Option<String>,
    params: Option<String>,
}

pub struct JsPkg {
    name: String,
    main: String,
    description: String,
    params: String,
    enable_fetch: bool,
    enable_console: bool,
    enable_commonjs: bool,
}
pub type JsPkgRef = Arc<JsPkg>;

fn register_clap(context: &mut Context) {
    
}

impl JsPkg {
    pub fn new(name: impl Into<String>,
               main: impl Into<String>,
               description: impl Into<String>,
               params: impl Into<String>) -> Self {
        JsPkg {
            name: name.into(),
            main: main.into(),
            description: description.into(),
            params: params.into(),
            enable_fetch: true,
            enable_console: true,
            enable_commonjs: true,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn main(&self) -> &str {
        self.main.as_str()
    }

    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    pub fn params(&self) -> &str {
        self.params.as_str()
    }

    pub fn enable_fetch(&mut self, enable: bool) -> &mut Self {
        self.enable_fetch = enable;
        self
    }

    pub fn enable_console(&mut self, enable: bool) -> &mut Self {
        self.enable_console = enable;
        self
    }

    pub fn enable_commonjs(&mut self, enable: bool) -> &mut Self {
        self.enable_commonjs = enable;
        self
    }

    pub async fn run(&self, args: Vec<String>) -> JsPkgResult<()> {
        let enable_fetch = self.enable_fetch;
        let enable_console = self.enable_console;
        let enable_commonjs = self.enable_commonjs;
        let main = self.main.clone();
        let ret = tokio::task::spawn_blocking(move || {
            let mut js_engine = JsEngine::builder()
                .enable_fetch(enable_fetch)
                .enable_console(enable_console)
                .enable_commonjs(enable_commonjs)
                .build().map_err(into_js_pkg_err!("build js engine error"))?;

            js_engine.eval_file(Path::new(main.as_str()))
                .map_err(into_js_pkg_err!("eval file {}", main))?;

            let args = args.iter()
                .map(|v| JsValue::from(JsString::from(v.as_str())))
                .collect::<Vec<_>>();
            let args = JsArray::from_iter(args.into_iter(), js_engine.context());
            let result = js_engine.call("main", vec![JsValue::from(args)])
                .map_err(into_js_pkg_err!("call main"))?;
            if result.is_string() {
                println!("{}", result.as_string().unwrap().as_str().to_std_string_lossy());
            }

            Ok(())
        }).await.map_err(into_js_pkg_err!("run {}", self.name))?;
        ret
    }
}
pub struct JsPkgManager {
    js_cmd_path: PathBuf,
}

impl JsPkgManager {
    pub fn new(js_cmd_path: PathBuf) -> Self {
        JsPkgManager {
            js_cmd_path,
        }
    }

    pub async fn list_pkgs(&self) -> JsPkgResult<Vec<JsPkgRef>> {
        let dirs = self.js_cmd_path.read_dir()
            .map_err(into_js_pkg_err!("read {:?}", self.js_cmd_path))?;
        let mut pkgs = vec![];
        for entry in dirs {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    let cmd = self.load_pkg(&path).await?;
                    pkgs.push(cmd);
                }
            }
        }
        Ok(pkgs)
    }

    async fn load_pkg(&self, path: &Path) -> JsPkgResult<JsPkgRef> {
        let cfg_path = path.join("pkg.yaml");
        if cfg_path.exists() {
            let content = tokio::fs::read_to_string(cfg_path.as_path()).await
                .map_err(into_js_pkg_err!("read file {}", cfg_path.to_string_lossy().to_string()))?;
            let config = serde_yaml_ng::from_str::<JsPkgConfig>(content.as_str())
                .map_err(into_js_pkg_err!("parse {}", content))?;
            let main = config.main
                .map(|v| path.join(v).to_string_lossy().to_string())
                .unwrap_or(path.join("main.js").to_string_lossy().to_string());
            Ok(Arc::new(JsPkg::new(
                config.name,
                main,
                config.description.unwrap_or("".to_string()),
                config.params.unwrap_or("".to_string()),
            )))
        } else {
            let main_js = path.join("main.js");
            if !main_js.exists() {
                return Err(js_pkg_err!("{} not exists", main_js.to_string_lossy().to_string()));
            }
            if let Some(file_name) = path.file_name() {
                Ok(Arc::new(JsPkg::new(
                    file_name.to_string_lossy().to_string(),
                    main_js.to_string_lossy().to_string(),
                    "",
                    "",
                )))
            } else {
                Err(js_pkg_err!("{} not exists", main_js.to_string_lossy().to_string()))
            }
        }
    }

    pub async fn get_pkg(&self, name: impl Into<String>) -> JsPkgResult<JsPkgRef> {
        self.load_pkg(self.js_cmd_path.join(name.into()).as_path()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use buckyos_kit::init_logging;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_list_pkgs() {
        init_logging("test", false);
        // 创建临时目录
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path();

        // 创建测试包目录 pkg1
        let pkg1_path = test_path.join("pkg1");
        fs::create_dir_all(&pkg1_path).await.unwrap();
        let main_js_content = r#"
            export function main(args) {
                console.log("Hello from pkg1");
                return "pkg1 executed";
            }
        "#;
        fs::write(pkg1_path.join("main.js"), main_js_content).await.unwrap();

        // 创建测试包目录 pkg2
        let pkg2_path = test_path.join("pkg2");
        fs::create_dir_all(&pkg2_path).await.unwrap();
        let pkg2_yaml_content = r#"
            name: "pkg2"
            main: "index.js"
            description: "A test package"
            params: "test_params"
        "#;
        fs::write(pkg2_path.join("pkg.yaml"), pkg2_yaml_content).await.unwrap();
        let index_js_content = r#"
            export function main(args) {
                console.log("Hello from pkg2");
                console.log(args);
                return "pkg2 executed";
            }
        "#;
        fs::write(pkg2_path.join("index.js"), index_js_content).await.unwrap();

        let manager = JsPkgManager::new(test_path.to_path_buf());
        let pkgs = manager.list_pkgs().await.unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name(), "pkg1");
        assert_eq!(pkgs[1].name(), "pkg2");

        let pkg1 = pkgs[0].clone();
        let pkg2 = pkgs[1].clone();
        pkg2.run(vec!["arg1".to_string(), "arg2".to_string()]).await.unwrap();
    }
}