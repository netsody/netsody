use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Emitter::default()
        .add_instructions(&Git2Builder::default().sha(true).dirty(true).build()?)?
        .emit()?;
    Ok(())
}
