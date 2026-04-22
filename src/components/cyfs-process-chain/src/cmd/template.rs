use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
enum TemplatePatternSegment {
    Template(Vec<TemplateFragment>),
    WildcardRest,
}

#[derive(Clone, Debug)]
enum TemplateFragment {
    Literal(String),
    Capture(String),
}

#[derive(Clone, Debug)]
struct TemplateCapture {
    name: String,
    value: String,
}

#[derive(Clone, Debug)]
pub(crate) struct TemplateMatchResult {
    positional_captures: Vec<String>,
    named_captures: HashMap<String, String>,
    rest_segments: Vec<String>,
    has_wildcard_rest: bool,
}

impl TemplateMatchResult {
    pub(crate) fn positional_captures(&self) -> &[String] {
        &self.positional_captures
    }

    pub(crate) fn named_captures(&self) -> &HashMap<String, String> {
        &self.named_captures
    }

    pub(crate) fn rest_segments(&self) -> &[String] {
        &self.rest_segments
    }

    pub(crate) fn has_wildcard_rest(&self) -> bool {
        self.has_wildcard_rest
    }
}

pub(crate) struct TemplateMatcher {
    command_name: String,
    separator: char,
    ignore_case: bool,
}

impl TemplateMatcher {
    pub(crate) fn new(command_name: impl Into<String>, separator: char, ignore_case: bool) -> Self {
        Self {
            command_name: command_name.into(),
            separator,
            ignore_case,
        }
    }

    pub(crate) fn match_template(
        &self,
        value: &str,
        pattern: &str,
    ) -> Result<Option<TemplateMatchResult>, String> {
        let pattern_segments = self.parse_pattern(pattern)?;
        let value_segments: Vec<&str> = value.split(self.separator).collect();
        let mut positional_captures = Vec::new();
        let mut named_captures = HashMap::new();
        let mut value_index = 0usize;

        for segment in pattern_segments.iter() {
            match segment {
                TemplatePatternSegment::WildcardRest => {
                    let rest_segments = value_segments[value_index..]
                        .iter()
                        .map(|segment| (*segment).to_owned())
                        .collect();

                    return Ok(Some(TemplateMatchResult {
                        positional_captures,
                        named_captures,
                        rest_segments,
                        has_wildcard_rest: true,
                    }));
                }
                TemplatePatternSegment::Template(fragments) => {
                    if value_index >= value_segments.len() {
                        return Ok(None);
                    }
                    let segment_captures =
                        self.match_segment_template(fragments, value_segments[value_index])?;
                    let Some(segment_captures) = segment_captures else {
                        return Ok(None);
                    };

                    for capture in segment_captures {
                        positional_captures.push(capture.value.clone());
                        named_captures.insert(capture.name, capture.value);
                    }
                    value_index += 1;
                }
            }
        }

        if value_index == value_segments.len() {
            Ok(Some(TemplateMatchResult {
                positional_captures,
                named_captures,
                rest_segments: Vec::new(),
                has_wildcard_rest: false,
            }))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn rewrite(
        &self,
        value: &str,
        pattern: &str,
        template: &str,
    ) -> Result<Option<String>, String> {
        let Some(result) = self.match_template(value, pattern)? else {
            return Ok(None);
        };

        let mut rewritten_segments = Vec::new();
        for segment in template.split(self.separator) {
            if segment == "**" {
                if !result.has_wildcard_rest() {
                    let msg = format!(
                        "{} template '{}' uses '**' but pattern '{}' does not capture remaining segments",
                        self.command_name, template, pattern
                    );
                    error!("{}", msg);
                    return Err(msg);
                }

                rewritten_segments.extend(result.rest_segments().iter().cloned());
                continue;
            }

            let fragments = self.parse_segment_template(template, segment)?;
            let rewritten_segment =
                render_template_fragments(&fragments, result.named_captures(), template)?;
            rewritten_segments.push(rewritten_segment);
        }

        let separator = self.separator.to_string();
        Ok(Some(rewritten_segments.join(&separator)))
    }

    fn parse_pattern(&self, pattern: &str) -> Result<Vec<TemplatePatternSegment>, String> {
        let raw_segments: Vec<&str> = pattern.split(self.separator).collect();
        let mut segments = Vec::with_capacity(raw_segments.len());
        let mut seen_capture_names = HashSet::new();

        for (index, segment) in raw_segments.iter().enumerate() {
            if *segment == "**" {
                if index + 1 != raw_segments.len() {
                    let msg = format!(
                        "{} pattern '{}' contains '**' before the last segment",
                        self.command_name, pattern
                    );
                    error!("{}", msg);
                    return Err(msg);
                }
                segments.push(TemplatePatternSegment::WildcardRest);
                continue;
            }

            let fragments = self.parse_segment_template(pattern, segment)?;
            for fragment in fragments.iter() {
                if let TemplateFragment::Capture(name) = fragment {
                    if !seen_capture_names.insert(name.clone()) {
                        let msg = format!(
                            "Invalid {} pattern '{}': duplicate capture name '{}'",
                            self.command_name, pattern, name
                        );
                        error!("{}", msg);
                        return Err(msg);
                    }
                }
            }
            segments.push(TemplatePatternSegment::Template(fragments));
        }

        Ok(segments)
    }

    fn parse_segment_template(
        &self,
        pattern: &str,
        segment: &str,
    ) -> Result<Vec<TemplateFragment>, String> {
        let mut fragments = Vec::new();
        let mut literal_start = 0usize;
        let mut cursor = 0usize;

        while let Some(rel_open) = segment[cursor..].find('{') {
            let open = cursor + rel_open;
            if literal_start < open {
                fragments.push(TemplateFragment::Literal(
                    segment[literal_start..open].to_owned(),
                ));
            }

            let close = segment[open + 1..]
                .find('}')
                .map(|offset| open + 1 + offset)
                .ok_or_else(|| {
                    let msg = format!(
                        "Invalid {} pattern '{}': missing closing '}}' in segment '{}'",
                        self.command_name, pattern, segment
                    );
                    error!("{}", msg);
                    msg
                })?;

            let name = &segment[open + 1..close];
            if !is_valid_template_capture_name(name) {
                let msg = format!(
                    "Invalid {} pattern '{}': capture name '{}' must match [A-Za-z_][A-Za-z0-9_]*",
                    self.command_name, pattern, name
                );
                error!("{}", msg);
                return Err(msg);
            }

            fragments.push(TemplateFragment::Capture(name.to_owned()));
            cursor = close + 1;
            literal_start = cursor;
        }

        if literal_start < segment.len() {
            fragments.push(TemplateFragment::Literal(
                segment[literal_start..].to_owned(),
            ));
        }

        if fragments.is_empty() {
            fragments.push(TemplateFragment::Literal(String::new()));
        }

        Ok(fragments)
    }

    fn match_segment_template(
        &self,
        fragments: &[TemplateFragment],
        value: &str,
    ) -> Result<Option<Vec<TemplateCapture>>, String> {
        self.match_segment_from(fragments, value, 0, 0)
    }

    fn match_segment_from(
        &self,
        fragments: &[TemplateFragment],
        value: &str,
        fragment_index: usize,
        offset: usize,
    ) -> Result<Option<Vec<TemplateCapture>>, String> {
        if fragment_index == fragments.len() {
            return Ok((offset == value.len()).then(Vec::new));
        }

        match &fragments[fragment_index] {
            TemplateFragment::Literal(literal) => {
                if !segment_starts_with(&value[offset..], literal, self.ignore_case) {
                    return Ok(None);
                }

                self.match_segment_from(
                    fragments,
                    value,
                    fragment_index + 1,
                    offset + literal.len(),
                )
            }
            TemplateFragment::Capture(name) => {
                if fragment_index + 1 == fragments.len() {
                    return Ok(Some(vec![TemplateCapture {
                        name: name.clone(),
                        value: value[offset..].to_owned(),
                    }]));
                }

                for end in candidate_segment_end_offsets(value, offset) {
                    if let Some(mut rest) =
                        self.match_segment_from(fragments, value, fragment_index + 1, end)?
                    {
                        let mut captures = vec![TemplateCapture {
                            name: name.clone(),
                            value: value[offset..end].to_owned(),
                        }];
                        captures.append(&mut rest);
                        return Ok(Some(captures));
                    }
                }

                Ok(None)
            }
        }
    }
}

fn render_template_fragments(
    fragments: &[TemplateFragment],
    named_captures: &HashMap<String, String>,
    template: &str,
) -> Result<String, String> {
    let mut rendered = String::new();

    for fragment in fragments {
        match fragment {
            TemplateFragment::Literal(literal) => rendered.push_str(literal),
            TemplateFragment::Capture(name) => {
                let value = named_captures.get(name).ok_or_else(|| {
                    let msg = format!(
                        "Invalid template '{}': unknown capture name '{}'",
                        template, name
                    );
                    error!("{}", msg);
                    msg
                })?;
                rendered.push_str(value);
            }
        }
    }

    Ok(rendered)
}

fn is_valid_template_capture_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn segment_starts_with(value: &str, prefix: &str, ignore_case: bool) -> bool {
    match value.get(..prefix.len()) {
        Some(candidate) => segment_text_eq(candidate, prefix, ignore_case),
        None => false,
    }
}

fn segment_text_eq(left: &str, right: &str, ignore_case: bool) -> bool {
    if ignore_case {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn candidate_segment_end_offsets(value: &str, start: usize) -> Vec<usize> {
    let mut offsets = Vec::new();
    offsets.push(value.len());

    let tail = &value[start..];
    for (rel, _) in tail.char_indices() {
        if rel == 0 {
            continue;
        }
        offsets.push(start + rel);
    }

    offsets.sort_unstable();
    offsets.dedup();
    offsets.reverse();
    offsets
}
