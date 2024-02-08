#![feature(iter_intersperse)]

use sleigh_rs::disassembly::{self, ExprElement, Op, OpUnary, ReadScope};
use sleigh_rs::display::DisplayElement;
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
use std::fmt::Display;
use std::string::ToString;
use std::{
    collections::HashSet,
    error::Error,
    io::{self, stdout, Write},
};

trait ToStr {
    fn to_string(&self) -> &str;
}

trait ToString_ {
    fn to_string(&self) -> String;
}

trait ToStringSleigh {
    fn to_string(&self, sl: &Sleigh) -> String;
}

impl ToStr for CmpOp {
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

impl ToStr for Op {
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

impl ToStr for OpUnary {
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
        assert_eq!(stack.len(), 1);
        Ok(stack.pop().unwrap())
    }
}

impl<'a> Display for Expr<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
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
        };
        write!(f, "{}", str)
    }
}

impl ToString_ for &ConstraintValue {
    fn to_string(&self) -> String {
        Expr::try_from(*self).unwrap().to_string()
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
            let t = sl.table(produced_table.table);
            if let Some((op, v)) = verification {
                write!(
                    w,
                    "{} {} {}",
                    t.name().id_mapper(),
                    op.to_string(),
                    v.to_string()
                )?;
            } else {
                write!(w, "{}", t.name().token_field_mapper())?;
            }
        }
        TokenFieldCheck { field, op, value } => {
            let field = sl.token_field(*field);
            write!(
                w,
                "{} {} {}",
                field.name().id_mapper(),
                op.to_string(),
                value.to_string()
            )?;
        }
        SubPattern { location, pattern } => {
            write!(w, "ignored subpattern")?;
        }
    }
    Ok(())
}

impl ToStringSleigh for Verification {
    fn to_string(&self, sl: &Sleigh) -> String {
        let mut out = io::BufWriter::new(Vec::new());
        let _ = verify_codegen(&mut out, sl, self);
        String::from_utf8_lossy(out.buffer()).to_string()
    }
}

trait IdMapper {
    fn id_mapper(&self) -> String;
    fn token_field_mapper(&self) -> String;
    fn formater(&self) -> &str;
}

impl IdMapper for &str {
    fn id_mapper(&self) -> String {
        match *self {
            _ if self.starts_with("op") => format!("OP({}, {})", &self[2..4], &self[4..6]),
            _ if self.starts_with("R") => match &self[1..5] {
                "0004" => "R1".to_string(),
                "1115" => "R2".to_string(),
                "2731" => "R3".to_string(),
                _ => self.to_string(),
            },
            _ if self.starts_with("fcbit") => {
                format!("slice(inst->d, {}, {})", &self[5..7], &self[7..9])
            }
            _ if self.starts_with("fcond") => {
                format!("conds[slice(inst->d, {}, {})]", &self[5..7], &self[7..9])
            }
            "reg4" => "R4".to_string(),
            _ => self.to_string(),
        }
    }
    fn token_field_mapper(&self) -> String {
        match *self {
            _ if self.starts_with("R") => match &self[1..5] {
                "0004" => "get_reg1(inst)".to_string(),
                "1115" => "get_reg2(inst)".to_string(),
                "2731" => "get_reg3(inst)".to_string(),
                _ => self.to_string(),
            },
            _ if self.starts_with("fcbit") || self.starts_with("fcond") => {
                format!("slice(inst->d, {}, {})", &self[5..7], &self[7..9])
            }
            "reg4" => "get_reg4(inst)".to_string(),
            _ => self.to_string(),
        }
    }
    fn formater(&self) -> &str {
        match self {
            _ if self.starts_with("op") => "%x",
            _ if self.starts_with("fcbit") => "%d",
            _ if self.starts_with("fcond") => "%s",
            _ if self.starts_with("R") => "%s",
            _ => "%s",
        }
    }
}

fn instr_codegen(w: &mut impl Write, sl: &Sleigh, x: &Constructor) -> Result<(), Box<dyn Error>> {
    let mneumonic = x.display.mneumonic.as_ref().unwrap().as_str();
    // println!("{}: {:#?}", mneumonic, x);
    write!(w, "// {}\n", mneumonic)?;
    write!(w, "if (")?;
    for (i_expr, expr) in x.pattern.blocks.iter().enumerate() {
        match expr {
            Block::And {
                verifications,
                token_fields,
                ..
            } => {
                if i_expr > 0 {
                    write!(w, " && ")?;
                }
                /*                 let tokfs = token_fields
                .iter()
                .map(|x| sl.token_field(x.field).name().token_field_mapper()); */
                let verifs = verifications.iter().map(|x| x.to_string(sl));
                let allinone = verifs
                    /*                     .chain(verifs) */
                    .filter(|x| !x.is_empty())
                    .intersperse(" && ".to_string())
                    .collect::<String>();
                write!(w, "({})", allinone)?;
            }
            Block::Or { .. } => (),
        }
    }
    write!(w, ") {}\n", "{")?;
    write!(
        w,
        "\tinst->id = V850_{};\n",
        mneumonic.to_uppercase().replace('.', "_")
    )?;
    write!(w, "\tINSTR(\"{}\");\n", mneumonic)?;
    let xs = x
        .display
        .elements()
        .skip(1)
        .map(|ele| match ele {
            /*         DisplayElement::Varnode(_) => todo!(),
            DisplayElement::Context(_) => todo!(),
            DisplayElement::InstStart(_) => todo!(),
            DisplayElement::InstNext(_) => todo!(),
            DisplayElement::Disassembly(_) => todo!(), */
            DisplayElement::Table(t) => {
                let t = sl.table(*t);
                (t.name().formater().to_string(), t.name().id_mapper())
            }
            DisplayElement::TokenField(tok) => {
                let tok = sl.token_field(*tok);
                (tok.name().formater().to_string(), tok.name().id_mapper())
            }
            DisplayElement::Literal(ele) => (ele.clone(), "".to_string()),
            DisplayElement::Space => (" ".to_string(), "".to_string()),
            _ => (format!("{:?}", ele), "".to_string()),
        })
        .reduce(|acc, e| {
            let mid = if acc.1.is_empty() || e.1.is_empty() {
                ""
            } else {
                ", "
            };
            (acc.0 + e.0.as_str(), acc.1 + mid + e.1.as_str())
        });
    if let Some(ops) = xs {
        write!(w, "\tOPERANDS(\"{}\", {});\n", ops.0, ops.1)?;
    }
    write!(w, "\treturn true;\n")?;
    write!(w, "{}\n", "}")?;
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
    write!(&mut code, "return true;")?;
    Ok(())
}
