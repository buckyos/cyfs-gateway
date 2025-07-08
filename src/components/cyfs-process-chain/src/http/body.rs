use serde_json::Value as JsonValue;
use toml::Value as TomlValue;
use xmltree::{Element, XMLNode};

struct PathParser {}

impl PathParser {
    fn parse_path(path: &str) -> Vec<&str> {
        if path.starts_with('/') {
            Self::parse_posix_path(path)
        } else {
            Self::parse_normal_path(path)
        }
    }

    // Normal path, like a.[0].c
    fn parse_normal_path(path: &str) -> Vec<&str> {
        path.split(|c| c == '.' || c == '[' || c == ']')
            .filter(|s| !s.is_empty())
            .collect()
    }

    // POSIX like path, like /a/0/c
    fn parse_posix_path(path: &str) -> Vec<&str> {
        assert!(path.starts_with('/'));

        let parts = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>();
        parts
    }
}

pub trait JSONModifier {
    fn get(&self, path: &str) -> Result<Option<JsonValue>, String>;
    fn set(&mut self, path: &str, value: JsonValue) -> Result<(), String>;
    fn remove(&mut self, path: &str) -> Result<Option<JsonValue>, String>;
}

// JSON impl
impl JSONModifier for JsonValue {
    fn get(&self, path: &str) -> Result<Option<JsonValue>, String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for part in parts {
            match current {
                JsonValue::Object(map) => match map.get(part) {
                    Some(value) => current = value,
                    None => return Ok(None),
                },
                JsonValue::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        match arr.get(index) {
                            Some(value) => current = value,
                            None => return Ok(None),
                        }
                    } else {
                        let msg = format!("Invalid array index: {}", part);
                        warn!("{}", msg);
                        return Err(msg);
                    }
                }
                _ => return Ok(Some(current.clone())),
            }
        }

        Ok(Some(current.clone()))
    }

    fn set(&mut self, path: &str, value: JsonValue) -> Result<(), String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            match current {
                JsonValue::Object(map) => {
                    if is_last {
                        map.insert(part.to_string(), value);
                        break;
                    } else {
                        current = map
                            .entry(*part)
                            .or_insert(JsonValue::Object(serde_json::Map::new()));
                    }
                }
                JsonValue::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        if is_last {
                            if index < arr.len() {
                                arr[index] = value;
                            } else {
                                arr.push(value);
                            }
                            break;
                        } else {
                            while arr.len() <= index {
                                // Fill the array with empty objects
                                arr.push(JsonValue::Object(serde_json::Map::new()));
                            }
                            current = &mut arr[index];
                        }
                    } else {
                        let msg = format!("Invalid array index: {}", part);
                        warn!("{}", msg);
                        return Err(msg);
                    }
                }
                _ => {
                    let msg = format!("Invalid path: {}", part);
                    warn!("{}", msg);
                    return Err(msg);
                }
            }
        }

        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<Option<JsonValue>, String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            match current {
                JsonValue::Object(map) => {
                    if is_last {
                        let value = map.remove(*part);
                        return Ok(value);
                    } else {
                        match map.get_mut(*part) {
                            Some(value) => current = value,
                            None => {
                                // FIXME: return error or just ignore?
                                return Ok(None);
                            }
                        }
                    }
                }
                JsonValue::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        if is_last {
                            if index < arr.len() {
                                let value = arr.remove(index);
                                return Ok(Some(value));
                            } else {
                                let msg = format!("Index out of bounds: {}", index);
                                warn!("{}", msg);

                                // FIXME: return error or just ignore?
                                return Ok(None);
                            }
                        } else {
                            match arr.get_mut(index) {
                                Some(value) => current = value,
                                None => {
                                    let msg = format!("Index not found: {}", index);
                                    warn!("{}", msg);
                                    return Ok(None);
                                }
                            }
                        }
                    } else {
                        let msg = format!("Invalid array index: {}", part);
                        warn!("{}", msg);
                        return Err(msg);
                    }
                }
                _ => {
                    let msg = format!("Invalid path: {}", part);
                    warn!("{}", msg);

                    // FIXME: return error or just ignore?
                    return Err(msg);
                }
            }
        }

        Ok(None)
    }
}

// TOML Store
pub trait TomlModifier {
    fn get(&self, path: &str) -> Result<Option<TomlValue>, String>;
    fn set(&mut self, path: &str, value: TomlValue) -> Result<(), String>;
    fn remove(&mut self, path: &str) -> Result<Option<TomlValue>, String>;
}

impl TomlModifier for TomlValue {
    fn get(&self, path: &str) -> Result<Option<TomlValue>, String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (_i, part) in parts.iter().enumerate() {
            match current {
                TomlValue::Table(map) => match map.get(*part) {
                    Some(value) => current = value,
                    None => return Ok(None),
                },
                TomlValue::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        match arr.get(index) {
                            Some(value) => current = value,
                            None => return Ok(None),
                        }
                    } else {
                        let msg = format!("Invalid array index: {}", part);
                        warn!("{}", msg);
                        return Err(msg);
                    }
                }
                _ => return Ok(Some(current.clone())),
            }
        }

        Ok(Some(current.clone()))
    }

    fn set(&mut self, path: &str, value: TomlValue) -> Result<(), String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            match current {
                TomlValue::Table(map) => {
                    if is_last {
                        map.insert(part.to_string(), value);
                        break;
                    } else {
                        current = map
                            .entry(*part)
                            .or_insert(TomlValue::Table(toml::map::Map::new()));
                    }
                }
                TomlValue::Array(arr) => {
                    let index = part.parse::<usize>().map_err(|_| {
                        let msg =
                            format!("Array index '{}' must be a number at position {}", part, i);
                        warn!("{}", msg);
                        msg
                    })?;

                    if is_last {
                        if index < arr.len() {
                            arr[index] = value;
                        } else {
                            arr.push(value);
                        }

                        break;
                    } else {
                        while arr.len() <= index {
                            // Fill the array with empty objects
                            arr.push(TomlValue::Table(toml::map::Map::new()));
                        }
                        current = &mut arr[index];
                    }
                }
                _ => {
                    let msg = format!("Invalid path: {}", part);
                    warn!("{}", msg);
                    return Err(msg);
                }
            }
        }

        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<Option<TomlValue>, String> {
        let parts = PathParser::parse_path(path);

        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            match current {
                TomlValue::Table(map) => {
                    if is_last {
                        return Ok(map.remove(*part));
                    } else {
                        match map.get_mut(*part) {
                            Some(value) => current = value,
                            None => return Ok(None),
                        }
                    }
                }
                TomlValue::Array(arr) => {
                    let index = part.parse::<usize>().map_err(|_| {
                        let msg =
                            format!("Array index '{}' must be a number at position {}", part, i);
                        warn!("{}", msg);
                        msg
                    })?;
                    if is_last {
                        if index < arr.len() {
                            return Ok(Some(arr.remove(index)));
                        } else {
                            let msg = format!("Index '{}' not found", index);
                            warn!("{}", msg);
                            return Ok(None);
                        }
                    } else {
                        match arr.get_mut(index) {
                            Some(value) => current = value,
                            None => {
                                let msg = format!("Index '{}' not found", index);
                                warn!("{}", msg);
                                return Ok(None);
                            }
                        }
                    }
                }
                _ => {
                    let msg = format!("Invalid path: {}", part);
                    warn!("{}", msg);

                    return Err(msg);
                }
            }
        }

        Ok(None)
    }
}

pub trait XmlModifier {
    fn get(&self, path: &str) -> Result<Option<Element>, String>;
    fn set(&mut self, path: &str, value: Element) -> Result<(), String>;
    fn remove(&mut self, path: &str) -> Result<Option<Element>, String>;
}

impl XmlModifier for Element {
    fn get(&self, path: &str) -> Result<Option<Element>, String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            if let Ok(index) = part.parse::<usize>() {
                match current.children.get(index) {
                    Some(value) => {
                        current = value.as_element().ok_or_else(|| {
                            let msg =
                                format!("Index '{}' is not an element at position {}", index, i);
                            warn!("{}", msg);
                            msg
                        })?
                    }
                    None => return Ok(None),
                }
            } else {
                match current
                    .children
                    .iter()
                    .filter_map(|n| n.as_element())
                    .find(|e| e.name == *part)
                {
                    Some(value) => current = value,
                    None => return Ok(None),
                }
            }
        }
        Ok(Some(current.clone()))
    }

    /*
    fn set(&mut self, path: &str, value: Element) -> Result<(), String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            if let Ok(index) = part.parse::<usize>() {
                while current.children.len() <= index {
                    let element = Element::new("item");
                    current.children.push(XMLNode::Element(element));
                }
                if is_last {
                    current.children[index] = XMLNode::Element(value);
                    break;
                } else {
                    current = current.children[index].as_mut_element().unwrap();
                }
            } else {
                let child_opt = {
                    let child = current.children.iter_mut()
                        .filter_map(|n| n.as_mut_element())
                        .find(|e| e.name == *part);
                    child
                };

                if let Some(child) = child_opt {
                    if is_last {
                        *child = value;
                        break;
                    }
                    current = child;
                } else {
                    let new_elem = if is_last {
                        value.clone()
                    } else {
                        Element::new(*part)
                    };
                    current.children.push(XMLNode::Element(new_elem));
                    if !is_last {
                        current = current.children.last_mut().unwrap().as_mut_element().unwrap();
                    }
                }
            }
        }

        Ok(())
    }
    */

    fn set(&mut self, path: &str, value: Element) -> Result<(), String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;

        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;

            if let Ok(index) = part.parse::<usize>() {
                while current.children.len() <= index {
                    let element = Element::new("item");
                    current.children.push(XMLNode::Element(element));
                }

                if is_last {
                    current.children[index] = XMLNode::Element(value);
                    break;
                } else {
                    current = current.children[index].as_mut_element().unwrap();
                }
            } else {
                // 第一步：先用immutable借用找到位置
                let child_index_opt = current
                    .children
                    .iter()
                    .position(|node| node.as_element().map_or(false, |e| e.name == *part));

                if let Some(idx) = child_index_opt {
                    if is_last {
                        // 第二步：这里已经确定了元素位置，直接修改
                        current.children[idx] = XMLNode::Element(value);
                        break;
                    } else {
                        // 更新current为下一级元素
                        current = current.children[idx].as_mut_element().unwrap();
                        continue;
                    }
                } else {
                    // 元素不存在，插入新元素到children
                    let new_elem = if is_last {
                        value.clone()
                    } else {
                        Element::new(part)
                    };
                    current.children.push(XMLNode::Element(new_elem));
                    if is_last {
                        break;
                    }
                    current = current
                        .children
                        .last_mut()
                        .unwrap()
                        .as_mut_element()
                        .unwrap();
                }
            }
        }
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<Option<Element>, String> {
        let parts = PathParser::parse_path(path);
        let mut current = self;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            if let Ok(index) = part.parse::<usize>() {
                if is_last {
                    if index < current.children.len() {
                        let removed = current.children.remove(index);
                        return Ok(removed.as_element().cloned());
                    } else {
                        let msg = format!("Index '{}' out of bounds", index);
                        warn!("{}", msg);

                        // FIXME: return error or just ignore?
                        return Ok(None);
                    }
                } else {
                    current = current
                        .children
                        .get_mut(index)
                        .and_then(|n| n.as_mut_element())
                        .ok_or_else(|| format!("Index '{}' not found at position {}", index, i))?;
                }
            } else {
                let child_index = current
                    .children
                    .iter()
                    .position(|n| n.as_element().map_or(false, |e| e.name == *part));
                if let Some(index) = child_index {
                    if is_last {
                        let removed = current.children.remove(index);
                        return Ok(removed.as_element().cloned());
                    } else {
                        current = current.children[index]
                            .as_mut_element()
                            .ok_or_else(|| format!("Key '{}' not found at position {}", part, i))?;
                    }
                } else {
                    return Err(format!("Key '{}' not found at position {}", part, i));
                }
            }
        }
        Ok(None)
    }
}
