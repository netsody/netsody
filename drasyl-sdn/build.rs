use vergen_git2::{BuildBuilder, CargoBuilder, Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Emitter::default()
        .add_instructions(&BuildBuilder::default().build_timestamp(true).build()?)?
        .add_instructions(&CargoBuilder::default().debug(true).features(true).build()?)?
        .add_instructions(&Git2Builder::default().sha(true).dirty(true).build()?)?
        .emit()?;
    Ok(())
}
