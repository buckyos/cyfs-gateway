use super::chain::ProcessChain;
use crate::block::*;
use std::str::FromStr;
use xmltree::Element;

/**
 * Process chain in xml format, at least one block is required in the chain.
 *
<root>
</process_chain id="main_http_server">
    <block type="process">
    </block>
</process_chain>

</process_chain id="main_http_server.post">
    <block type="rewrite">
    </block>
</process_chain>
</root>
 */

pub struct ProcessChainParser {}

impl ProcessChainParser {
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

                let id = id.unwrap();
                let mut chain_item = ProcessChain::new(id.to_string());

                info!("Will parse process chain: {}", id);

                // Load all blocks into vec
                for block in &process_chain.children {
                    if let xmltree::XMLNode::Element(block) = block {
                        let block = Self::load_block(block)?;
                        chain_item.add_block(block);
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
        // First load block type
        let block_type = block.attributes.get("type").ok_or_else(|| {
            let msg = format!("Block must have a type: {:?}", block.attributes);
            error!("{}", msg);
            msg
        })?;

        // Try to parse block type
        let block_type = BlockType::from_str(block_type).map_err(|e| {
            let msg = format!("Invalid block type: {}, {}", block_type, e);
            error!("{}", msg);
            msg
        })?;

        let block_parser = BlockParser::new(block_type);

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
