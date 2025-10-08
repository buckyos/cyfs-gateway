use crate::chain::*;
use crate::block::*;
use xmltree::Element;
use serde::Deserialize;
use std::sync::Arc;

/**
 * Process chain in xml format, at least one block is required in the chain.
 *
<root>
<process_chain id="main_http_server" priority="100">
    <block id="process">
    </block>
</process_chain>

<process_chain id="main_http_server.post" priority="200">
    <block id="rewrite">
    </block>
</process_chain>
</root>
 */

pub struct ProcessChainXMLLoader {}

impl ProcessChainXMLLoader {
    pub fn load_process_chain_lib(id: &str, priority: i32, config: &str) -> Result<ProcessChainLibRef, String> {
        let chains = Self::parse(config)?;
        let chains = chains
            .into_iter()
            .map(|chain| Arc::new(chain))
            .collect::<Vec<_>>();

        let lib = ProcessChainListLib::new(id, priority, chains);
        let lib = Arc::new(Box::new(lib) as Box<dyn ProcessChainLib>);

        Ok(lib)
    }

    pub fn parse(config: &str) -> Result<Vec<ProcessChain>, String> {
        // First parse config in xml format
        let root = Element::parse(config.as_bytes()).map_err(|e| {
            let msg = format!("Parse process chain config xml error: {}", e);
            error!("{}", msg);
            msg
        })?;

        // Traverse the process chain list
        let mut process_chain_list = Vec::new();
        for process_chain in &root.children {
            if let xmltree::XMLNode::Element(process_chain) = process_chain {
                let id = process_chain.attributes.get("id");
                if id.is_none() {
                    let msg = format!(
                        "Process chain must have an id: {:?}",
                        process_chain.attributes
                    );
                    error!("{}", msg);
                    return Err(msg);
                }

                let priority = process_chain
                    .attributes
                    .get("priority")
                    .and_then(|p| p.parse::<i32>().ok())
                    .unwrap_or(0); // Default priority is 0 if not specified

                let id = id.unwrap();
                let mut chain_item = ProcessChain::new(id.to_string(), priority);

                info!("Will parse process chain: {}", id);

                // Load all blocks into vec
                for block in &process_chain.children {
                    if let xmltree::XMLNode::Element(block) = block {
                        let block = Self::load_block(block)?;
                        chain_item.add_block(block)?;
                    }
                }

                // At least one block is required in the chain
                if chain_item.get_blocks().is_empty() {
                    let msg = format!(
                        "Process chain must have at least one block: {}",
                        id,
                    );
                    error!("{}", msg);
                    return Err(msg);
                }

                process_chain_list.push(chain_item);
            }
        }

        Ok(process_chain_list)
    }

    fn load_block(block: &xmltree::Element) -> Result<Block, String> {
        // First load block id
        let id = block.attributes.get("id").ok_or_else(|| {
            let msg = format!("Block must have an id: {:?}", block.attributes);
            error!("{}", msg);
            msg
        })?;


        let block_parser = BlockParser::new(id);

        let content = block.get_text().ok_or_else(|| {
            let msg = format!("Block must have content: {:?}", block.attributes);
            error!("{}", msg);
            msg
        })?;

        // Parse block content
        let item = block_parser.parse(&content).map_err(|e| {
            let msg = format!("Parse block error: {}, {}", content, e);
            error!("{}", msg);
            msg
        })?;

        Ok(item)
    }
}


pub struct ProcessChainJSONLoader {}

#[derive(Deserialize, Debug)]
pub struct ProcessChainJSONItem {
    pub id: String,
    pub priority: i32,
    pub blocks: Vec<BlockJSONItem>,
}

#[derive(Deserialize, Debug)]
pub struct BlockJSONItem {
    pub id: String,
    pub content: String,
}

impl ProcessChainJSONLoader {
    pub fn load_process_chain_lib(id: &str, priority: i32, content: &str) -> Result<ProcessChainLibRef, String> {
        let chains = Self::parse(content)?;
        let chains = chains
            .into_iter()
            .map(|chain| Arc::new(chain))
            .collect::<Vec<_>>();

        let lib = ProcessChainListLib::new(id, priority, chains);
        let lib = Arc::new(Box::new(lib) as Box<dyn ProcessChainLib>);

        Ok(lib)
    }

    // Load process chain list from json format
    pub fn parse(config: &str) -> Result<Vec<ProcessChain>, String> {
        let list: Vec<ProcessChainJSONItem> = serde_json::from_str(config).map_err(|e| {
            let msg = format!("Parse process chain config json error: {}", e);
            error!("{}", msg);
            msg
        })?;

        Self::parser_direct(list)
    }

    pub fn parser_direct(list: Vec<ProcessChainJSONItem>) -> Result<Vec<ProcessChain>, String> {
        let mut process_chain_list = Vec::new();
        for item in list {
            let mut chain_item = ProcessChain::new(item.id.clone(), item.priority);

            info!("Will parse process chain: {}", item.id);

            for block in item.blocks {
                let block = Self::load_block(&block)?;
                chain_item.add_block(block)?;
            }

            // At least one block is required in the chain
            if chain_item.get_blocks().is_empty() {
                let msg = format!(
                    "Process chain must have at least one block: {}",
                    item.id,
                );
                error!("{}", msg);
                return Err(msg);
            }

            process_chain_list.push(chain_item);
        }

        Ok(process_chain_list)
    }

    fn load_block(block: &BlockJSONItem) -> Result<Block, String> {
        let block_parser = BlockParser::new(&block.id);

        // Parse block content
        let item = block_parser.parse(&block.content).map_err(|e| {
            let msg = format!("Parse block error: {}, {}", block.content, e);
            error!("{}", msg);
            msg
        })?;

        Ok(item)
    }
}