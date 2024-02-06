use std::error::Error;
use sleigh_rs::file_to_sleigh;

fn main() -> Result<(), Box<dyn Error>> {
    let path = "../ghidra/Ghidra/Processors/v850/data/languages/v850.slaspec";
    let sleigh = file_to_sleigh(path.as_ref())?;
    println!("{:?}", sleigh);
    Ok(())
}
