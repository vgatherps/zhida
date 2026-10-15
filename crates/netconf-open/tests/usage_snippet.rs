//! docs/USAGE.md shows the setup code from examples/setup.rs inline, because Markdown cannot
//! include a file. The build compiles the example; this test fails when the inline copy drifts.

const USAGE: &str = include_str!("../../../docs/USAGE.md");
const EXAMPLE: &str = include_str!("../examples/setup.rs");

#[test]
fn usage_setup_block_matches_example() {
    let from_heading = &USAGE[USAGE
        .find("\nSetup for one TCP socket looks like this.")
        .expect("USAGE.md lost the setup paragraph")..];
    let start = from_heading.find("\n```rust\n").expect("no rust block after the setup paragraph")
        + "\n```rust\n".len();
    let block = &from_heading[start..];
    let end = block.find("\n```\n").expect("setup block is not closed") + 1;
    assert_eq!(&block[..end], EXAMPLE, "docs/USAGE.md setup block differs from examples/setup.rs");
}
