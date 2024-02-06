use sleigh2rust::generate_disassembler;
use sleigh_rs::file_to_sleigh;
use std::{collections::HashSet, error::Error, hash::RandomState, ops::Sub};

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
    let instr_set: HashSet<&str, RandomState> =
        HashSet::from_iter(instr.iter().map(|x| x.as_str()));

    let sel = [
        "absf.d",
        "absf.s",
        "addf.d",
        "addf.s",
        "ceilf.dl",
        "ceilf.dul",
        "ceilf.duw",
        "ceilf.dw",
        "ceilf.sl",
        "ceilf.sul",
        "ceilf.suw",
        "ceilf.sw",
        "cmovf.d",
        "cmovf.s",
        "cmpf.d",
        "cmpf.s",
        "cvtf.dl",
        "cvtf.ds",
        "cvtf.dul",
        "cvtf.duw",
        "cvtf.dw",
        "cvtf.ld",
        "cvtf.ls",
        "cvtf.sd",
        "cvtf.sl",
        "cvtf.sul",
        "cvtf.suw",
        "cvtf.sw",
        "cvtf.uld",
        "cvtf.uls",
        "cvtf.uwd",
        "cvtf.uws",
        "cvtf.wd",
        "cvtf.ws",
        "divf.d",
        "divf.s",
        "floorf.dl",
        "floorf.dul",
        "floorf.duw",
        "floorf.dw",
        "floorf.sl",
        "floorf.sul",
        "floorf.suw",
        "floorf.sw",
        "maddf.s",
        "maxf.d",
        "maxf.s",
        "minf.d",
        "minf.s",
        "msubf.s",
        "mulf.d",
        "mulf.s",
        "negf.d",
        "negf.s",
        "nmaddf.s",
        "nmsubf.s",
        "recipf.d",
        "recipf.s",
        "rsqrtf.d",
        "rsqrtf.s",
        "sqrtf.d",
        "sqrtf.s",
        "subf.d",
        "subf.s",
        "trfsr",
        "trncf.dl",
        "trncf.dul",
        "trncf.duw",
        "trncf.dw",
        "trncf.sl",
        "trncf.sul",
        "trncf.suw",
        "trncf.sw",
    ];
    let sel = HashSet::from(sel);
    let mut instr_sel = instr_set.intersection(&sel).collect::<Vec<_>>();
    let instr_lack_s = sel.sub(&instr_set);
    let mut instr_lack = Vec::from_iter(instr_lack_s.iter());
    instr_sel.sort();
    instr_lack.sort();

/*     println!("{:#?}", instr);
    println!("{:#?}", instr_sel);
    println!("{:#?}", instr_lack); */
    assert_eq!(sel.len(), instr_sel.len());

    

    Ok(())
}
