use crate::{LintConfig, classify_parse_error, lint_xml_content};

#[test]
fn test_lint_undefined_var() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local a=1;
      echo $a;
      echo $missing;
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(ret.iter().any(|d| d.code == "PC-LINT-1001"));
    assert_eq!(ret.iter().filter(|d| d.code == "PC-LINT-1001").count(), 1);
}

#[test]
fn test_lint_unused_var() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local temp=1;
      return --from lib "ok";
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(ret.iter().any(|d| d.code == "PC-LINT-3001"));
}

#[test]
fn test_lint_loose_compare() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local a=1;
      if $a == "1" then
        return --from lib "ok";
      end
      return --from lib "ok";
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(ret.iter().any(|d| d.code == "PC-LINT-4001"));
}

#[test]
fn test_lint_optional_var_access_reduces_false_positive() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      echo ${missing?.country};
      echo ${missing ?? "unknown"};
      return --from lib "ok";
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(
        !ret.iter().any(|d| d.code == "PC-LINT-1001"),
        "optional/coalesce access should not emit undefined-var error: {:?}",
        ret
    );
}

#[test]
fn test_lint_dynamic_path_tracks_index_variable() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local coll="demo";
      echo $coll[$key];
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(
        ret.iter()
            .any(|d| d.code == "PC-LINT-1001" && d.message.contains("key")),
        "dynamic index variable should be tracked as read: {:?}",
        ret
    );
}

#[test]
fn test_lint_overwrite_before_read() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local a=1;
      local a=2;
      echo $a;
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(ret.iter().any(|d| d.code == "PC-LINT-3003"));
}

#[test]
fn test_lint_shadowing_warning() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      chain token=1;
      echo $token;
      local token=2;
      echo $token;
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(ret.iter().any(|d| d.code == "PC-LINT-3002"));
}

#[test]
fn test_lint_rewrite_regex_template_dollar_context() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local path="/a";
      rewrite-reg $path '^/(.*)$' "/\$user/\$1";
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(
        !ret.iter()
            .any(|d| d.code == "PC-LINT-1001" && d.message.contains("user")),
        "rewrite-reg template '$user' should not be treated as DSL var read: {:?}",
        ret
    );
    assert!(ret.iter().any(|d| d.code == "PC-LINT-4101"));
}

#[test]
fn test_lint_rewrite_regex_multi_digit_capture_warning() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      local path="/a";
      rewrite-reg $path '^/(.*)$' "/\$10";
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(ret.iter().any(|d| d.code == "PC-LINT-4102"));
}

#[test]
fn test_classify_parse_error_for_composite_command_substitution() {
    let err = "Parse statements error: echo $(eq 1 1 && echo ok);, Failure(Error { input: \" && echo ok\", code: Tag })";
    let classified = classify_parse_error(err);
    assert!(classified.is_some());
    let (code, message) = classified.unwrap();
    assert_eq!(code, "PC-LINT-4103");
    assert!(message.contains("$(...)"));
}

#[test]
fn test_lint_for_loop_vars_are_visible_inside_loop() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      for idx, item in $REQ.items then
        echo $idx $item;
      end
      return --from lib "ok";
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(
        !ret.iter().any(|d| d.code == "PC-LINT-1001"),
        "for-loop vars should be visible inside loop body: {:?}",
        ret
    );
}

#[test]
fn test_lint_for_loop_vars_are_not_visible_outside_loop() {
    let xml = r#"
<root>
  <process_chain id="main">
    <block id="entry"><![CDATA[
      for item in $REQ.items then
        echo $item;
      end
      echo $item;
    ]]></block>
  </process_chain>
</root>
"#;
    let config = LintConfig::default();
    let ret = lint_xml_content(xml, "test.xml", "test_lib", &config).unwrap();
    assert!(
        ret.iter()
            .any(|d| d.code == "PC-LINT-1001" && d.message.contains("item")),
        "loop var should be reported undefined outside loop: {:?}",
        ret
    );
}
