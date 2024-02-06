use sleigh2rust::generate_disassembler;
use sleigh_rs::file_to_sleigh;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let path = "../ghidra/Ghidra/Processors/V850/data/languages/V850.slaspec";
    let sleigh = file_to_sleigh(path.as_ref())?;
    // generate_disassembler(path)?;
    // register?
    println!(
        "{:?}",
        sleigh
            .varnodes()
            .iter()
            .map(|x| x.name())
            .collect::<Vec<_>>()
    );
    // macro?
    println!("{:?}", sleigh.pcode_macros()[0]);

    // instr kind?
    println!(
        "{:?}",
        sleigh.tokens().iter().map(|x| x.name()).collect::<Vec<_>>()
    );
    println!(
        "{:?}",
        sleigh
            .token_fields()
            .iter()
            .map(|x| x.name())
            .collect::<Vec<_>>()
    );
    println!(
        "{:?}",
        sleigh.tables().iter().map(|x| x.name()).collect::<Vec<_>>()
    );

    let tbl = sleigh.table(sleigh.instruction_table);

    let mut instr = tbl
        .constructors()
        .iter()
        .map(|x| x.display.mneumonic.clone().unwrap_or("".to_string()))
        .collect::<Vec<_>>();
    instr.sort();
    println!("{:#?}", instr);

    Ok(())
}
