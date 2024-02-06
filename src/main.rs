use sleigh_rs::disassembly::{self, ExprElement, Op, OpUnary, ReadScope};
use sleigh_rs::pattern::CmpOp;
use sleigh_rs::{
    file_to_sleigh,
    pattern::{
        Block,
        CmpOp::*,
        ConstraintValue,
        Verification::{self, *},
    },
    table::Constructor,
    Sleigh,
};
use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, write},
    io::{self, stdout, Write},
};

trait MyToString {
    fn to_string(&self) -> &str;
}

impl MyToString for CmpOp {
    fn to_string(&self) -> &str {
        match self {
            Eq => "==",
            Ne => "!=",
            Lt => "<",
            Gt => ">",
            Le => "<=",
            Ge => ">=",
        }
    }
}

impl MyToString for Op {
    fn to_string(&self) -> &str {
        match self {
            Op::Add => "+",
            Op::Sub => "-",
            Op::Mul => "*",
            Op::Div => "/",
            Op::And => "&&",
            Op::Or => "||",
            Op::Xor => "^",
            Op::Asr => ">>>",
            Op::Lsl => "<<",
        }
    }
}

impl MyToString for OpUnary {
    fn to_string(&self) -> &str {
        match self {
            OpUnary::Negation => "-",
            OpUnary::Negative => "~",
        }
    }
}

type OpBin = disassembly::Op;

#[derive(Debug)]
enum Expr<'a> {
    OpBin(&'a OpBin, Box<Expr<'a>>, Box<Expr<'a>>),
    OpUnary(&'a OpUnary, Box<Expr<'a>>),
    Value(&'a ReadScope),
}

impl<'a> TryFrom<&'a ConstraintValue> for Expr<'a> {
    type Error = std::io::Error;
    fn try_from(value: &'a ConstraintValue) -> Result<Self, Self::Error> {
        let mut stack = vec![];
        for x in value.expr().elements() {
            match x {
                ExprElement::Value { value, location } => stack.push(Expr::Value(value)),
                ExprElement::Op(x) => {
                    let v1 = Box::new(stack.pop().unwrap());
                    let v2 = Box::new(stack.pop().unwrap());
                    stack.push(Expr::OpBin(x, v2, v1));
                }
                ExprElement::OpUnary(x) => {
                    let value = Box::new(stack.pop().unwrap());
                    stack.push(Expr::OpUnary(x, value));
                }
            }
        }
        assert!(stack.len() == 1);
        Ok(stack.pop().unwrap())
    }
}

impl<'a> ToString for Expr<'a> {
    fn to_string(&self) -> String {
        match self {
            Expr::OpBin(op, v1, v2) => {
                format!(
                    "({}) {} ({})",
                    v1.to_string(),
                    op.to_string(),
                    v2.to_string()
                )
            }
            Expr::OpUnary(op, v) => format!("{}({})", op.to_string(), v.to_string()),
            Expr::Value(v) => match v {
                ReadScope::Integer(vi) => match vi {
                    sleigh_rs::Number::Positive(vp) => format!("0x{:x}", vp),
                    sleigh_rs::Number::Negative(vn) => format!("-0x{:x}", vn),
                },
                ReadScope::Context(_) => todo!(),
                ReadScope::TokenField(_) => todo!(),
                ReadScope::InstStart(_) => todo!(),
                ReadScope::InstNext(_) => todo!(),
                ReadScope::Local(_) => todo!(),
            },
        }
    }
}

fn verify_codegen(w: &mut impl Write, sl: &Sleigh, x: &Verification) -> Result<(), Box<dyn Error>> {
    match x {
        ContextCheck { context, op, value } => {
            write!(w, "ignored ContextCheck")?;
        }
        TableBuild {
            produced_table,
            verification,
        } => {
            write!(w, "ignored TableBuild")?;
        }
        TokenFieldCheck { field, op, value } => {
            let field = sl.token_field(*field);
            write!(
                w,
                "{} {} {}",
                field.name(),
                op.to_string(),
                Expr::try_from(value)?.to_string()
            )?;
        }
        SubPattern { location, pattern } => {
            write!(w, "ignored subpattern")?;
        }
    }
    Ok(())
}

fn instr_codegen(w: &mut impl Write, sl: &Sleigh, x: &Constructor) -> Result<(), Box<dyn Error>> {
    let mneumonic = x.display.mneumonic.as_ref().unwrap().as_str();
    //    println!("{}: {:#?}", mneumonic, x);
    write!(w, "// {}\n", mneumonic)?;
    for expr in x.pattern.blocks.iter() {
        match expr {
            Block::And { verifications, .. } => {
                write!(w, "if (")?;
                for (i, verify) in verifications.iter().enumerate() {
                    verify_codegen(w, sl, verify)?;
                    if i < verifications.len() - 1 {
                        write!(w, " && ")?;
                    }
                }
                write!(w, ") {}\n", "{}")?;
            }
            Block::Or { .. } => (),
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = "../ghidra/Ghidra/Processors/V850/data/languages/V850.slaspec";
    let sleigh: Sleigh = file_to_sleigh(path.as_ref())?;
    // generate_disassembler(path)?;
    // register?
    /*     println!(
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
    ); */

    let tbl = sleigh.table(sleigh.instruction_table);
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
    let instr_sel = tbl
        .constructors()
        .iter()
        .filter(|x| sel.contains(x.display.mneumonic.as_ref().unwrap().as_str()))
        .collect::<Vec<_>>();
    assert_eq!(sel.len(), instr_sel.len());

    let mut code = io::BufWriter::new(stdout());
    for x in instr_sel {
        instr_codegen(&mut code, &sleigh, x)?;
    }
    Ok(())
}
