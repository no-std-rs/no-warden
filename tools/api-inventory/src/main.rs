use quote::ToTokens;
use serde_json::{json, Value};
use std::{env, fs, path::Path};
use syn::{
    parse::Parser,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
    Token,
};
mod inventory;

fn tokens(value: &impl ToTokens) -> String {
    value.to_token_stream().to_string()
}

#[derive(Default)]
struct Extractor {
    file: String,
    function: Option<String>,
    builder: bool,
    conditions: Vec<String>,
    definitions: Vec<Value>,
    macros: Vec<Value>,
    calls: Vec<Value>,
    mounts: Vec<Value>,
    dynamic_routes: Vec<Value>,
    errors: Vec<String>,
}

impl<'ast> Visit<'ast> for Extractor {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        let name = function.sig.ident.to_string();
        let old_function = self.function.replace(name.clone());
        let old_builder = self.builder;
        self.builder = name == "routes"
            || name == "events_routes"
            || name == "main_routes"
            || name == "catchers";
        let old_conditions = self.conditions.clone();
        for attribute in &function.attrs {
            if attribute.path().is_ident("cfg") {
                self.conditions.push(tokens(&attribute.meta));
            }
            let kind = attribute.path().segments.last().unwrap().ident.to_string();
            if [
                "get", "post", "put", "patch", "delete", "head", "options", "route", "catch",
            ]
            .contains(&kind.as_str())
            {
                let syn::Meta::List(list) = &attribute.meta else {
                    panic!("non-list route attribute")
                };
                let args = Punctuated::<syn::Expr, Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .unwrap();
                let mut options = serde_json::Map::new();
                let mut positional = Vec::new();
                for arg in args {
                    match arg {
                        syn::Expr::Assign(assign) => {
                            let key = tokens(&assign.left);
                            let value = match *assign.right {
                                syn::Expr::Lit(literal) => match literal.lit {
                                    syn::Lit::Str(s) => json!(s.value()),
                                    syn::Lit::Int(n) => json!(n.base10_parse::<i64>().unwrap()),
                                    other => json!(tokens(&other)),
                                },
                                other => json!(tokens(&other)),
                            };
                            options.insert(key, value);
                        }
                        syn::Expr::Lit(literal) => positional.push(match literal.lit {
                            syn::Lit::Str(s) => json!(s.value()),
                            syn::Lit::Int(n) => json!(n.base10_parse::<i64>().unwrap()),
                            other => json!(tokens(&other)),
                        }),
                        other => positional.push(json!(tokens(&other))),
                    }
                }
                self.definitions.push(json!({
                    "kind":kind,"handler":name,"source":self.file,
                    "attribute_line":attribute.span().start().line,"function_line":function.span().start().line,
                    "positional":positional,"options":options,"conditions":self.conditions,
                }));
            }
        }
        visit::visit_item_fn(self, function);
        self.function = old_function;
        self.builder = old_builder;
        self.conditions = old_conditions;
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        visit::visit_expr(self, &expression.cond);
        let count = self.conditions.len();
        for attr in &expression.attrs {
            if attr.path().is_ident("cfg") {
                self.conditions.push(tokens(&attr.meta));
            }
        }
        self.conditions.push(tokens(&expression.cond));
        visit::visit_block(self, &expression.then_branch);
        self.conditions.truncate(count);
        if let Some((_, branch)) = &expression.else_branch {
            self.conditions
                .push(format!("!({})", tokens(&expression.cond)));
            visit::visit_expr(self, branch);
            self.conditions.truncate(count);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let kind = mac.path.segments.last().unwrap().ident.to_string();
        if kind == "routes" || kind == "catchers" {
            match Punctuated::<syn::Path, Token![,]>::parse_terminated.parse2(mac.tokens.clone()) {
                Ok(paths) => self.macros.push(json!({
                    "kind":kind,"source":self.file,"function":self.function,
                    "line":mac.span().start().line,"handlers":paths.iter().map(tokens).collect::<Vec<_>>(),
                    "conditions":self.conditions,
                })),
                Err(error) => self.errors.push(format!("{}:{}: {error}", self.file, mac.span().start().line)),
            }
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let segments = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>();
            if segments
                .windows(2)
                .any(|p| p[0] == "Route" && ["new", "ranked"].contains(&p[1].as_str()))
            {
                self.dynamic_routes.push(json!({"source":self.file,"line":call.span().start().line,"constructor":tokens(&path.path)}));
            }
        }
        if self.builder {
            if let syn::Expr::Path(path) = &*call.func {
                self.calls.push(json!({"source":self.file,"function":self.function,"callee":tokens(&path.path),"line":call.span().start().line,"conditions":self.conditions}));
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "mount" || call.method == "register" {
            self.mounts.push(json!({"kind":call.method.to_string(),"source":self.file,"function":self.function,"line":call.method.span().start().line,"arguments":call.args.iter().map(tokens).collect::<Vec<_>>(),"conditions":self.conditions}));
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn walk(root: &Path, path: &Path, extractor: &mut Extractor) {
    let mut children = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    children.sort();
    for child in children {
        if child.is_dir() {
            walk(root, &child, extractor);
        } else if child.extension().is_some_and(|ext| ext == "rs") {
            extractor.file = child.strip_prefix(root).unwrap().display().to_string();
            let source = fs::read_to_string(&child).unwrap();
            let parsed = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", child.display()));
            extractor.visit_file(&parsed);
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("API inventory: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut source = None;
    let mut sha = None;
    let mut check = None;
    let mut output = None;
    let mut raw_ast = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source" => source = Some(args.next().ok_or("--source requires a directory")?),
            "--sha" => sha = Some(args.next().ok_or("--sha requires a commit SHA")?),
            "--check" => check = Some(args.next().ok_or("--check requires a JSON file")?),
            "--output" => output = Some(args.next().ok_or("--output requires a file")?),
            "--ast" => raw_ast = true,
            "--help" => {
                println!("no-warden-api-inventory --source DIR [--sha COMMIT] [--output FILE | --check FILE] [--ast]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    if check.is_some() && output.is_some() {
        return Err("--check and --output are mutually exclusive".into());
    }
    let baseline = check
        .as_ref()
        .map(|p| {
            fs::read_to_string(p)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
        })
        .transpose()?;
    let source = source.ok_or("--source DIR is required")?;
    let sha = sha.or_else(|| {
        baseline
            .as_ref()
            .and_then(|v| v["upstream"]["sha"].as_str().map(str::to_owned))
    });
    let root = Path::new(&source);
    let mut extractor = Extractor::default();
    walk(root, &root.join("src"), &mut extractor);
    let ast = json!({"definitions":extractor.definitions,"route_macros":extractor.macros,"factory_calls":extractor.calls,"mounts":extractor.mounts,"dynamic_route_constructors":extractor.dynamic_routes,"errors":extractor.errors});
    let generated = if raw_ast {
        ast
    } else {
        inventory::build(
            root,
            &sha.ok_or("--sha COMMIT is required when generating a new inventory")?,
            &ast,
        )?
    };
    if let Some(baseline) = baseline {
        if generated != baseline {
            return Err("generated facts differ from the checked inventory; regenerate and review the metadata/source-hash diff".into());
        }
        println!(
            "PASS: inventory matches {} registered routes and {} catchers",
            generated["counts"]["route_handlers"], generated["counts"]["catchers"]
        );
    } else {
        let rendered = inventory::render(&generated)?;
        if let Some(path) = output {
            fs::write(path, rendered).map_err(|e| e.to_string())?;
        } else {
            print!("{rendered}");
        }
    }
    Ok(())
}
