//! Original research helper: interprets the small route-vector factory language.
//! Unsupported factory expressions fail closed rather than silently losing routes.
use quote::ToTokens;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use syn::{parse::Parser, punctuated::Punctuated, spanned::Spanned, Token};

type Result<T> = std::result::Result<T, String>;
type Clause = BTreeMap<String, bool>;
type Key = (String, String);

fn text(v: &Value) -> &str {
    v.as_str().expect("AST text")
}
fn spelling(v: &impl ToTokens) -> String {
    v.to_token_stream()
        .to_string()
        .replace(" :: ", "::")
        .replace(" . ", ".")
        .replace(" ()", "()")
        .replace("cfg (", "cfg(")
}

fn mounted_uri(prefix: &str, uri: &str) -> String {
    // Rocket 0.5.1 normalizes the composed Origin, including empty path segments.
    // Keep declarations separately so this canonicalization never loses evidence.
    let (path, query) = uri
        .split_once('?')
        .map_or((uri, None), |(p, q)| (p, Some(q)));
    let parts = prefix
        .split('/')
        .chain(path.split('/'))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let mut joined = format!("/{}", parts.join("/"));
    if let Some(query) = query.filter(|q| !q.is_empty()) {
        joined.push('?');
        joined.push_str(query);
    }
    joined
}
fn module(source: &str) -> String {
    let source = source
        .strip_prefix("src/")
        .unwrap()
        .strip_suffix(".rs")
        .unwrap();
    if source == "main" {
        return "crate".into();
    }
    format!(
        "crate::{}",
        source
            .strip_suffix("/mod")
            .unwrap_or(source)
            .replace('/', "::")
    )
}
fn source_files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            result.extend(source_files(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            result.push(path);
        }
    }
    result.sort();
    Ok(result)
}
fn uses(tree: &syn::UseTree, prefix: &str, output: &mut BTreeMap<String, String>, scope: &str) {
    match tree {
        syn::UseTree::Path(p) => uses(&p.tree, &format!("{prefix}{}::", p.ident), output, scope),
        syn::UseTree::Group(g) => {
            for item in &g.items {
                uses(item, prefix, output, scope);
            }
        }
        syn::UseTree::Name(n) => {
            output.insert(
                format!("{scope}::{}", n.ident),
                format!("{prefix}{}", n.ident),
            );
        }
        syn::UseTree::Rename(n) => {
            output.insert(
                format!("{scope}::{}", n.rename),
                format!("{prefix}{}", n.ident),
            );
        }
        syn::UseTree::Glob(_) => {}
    }
}

#[derive(Clone, Debug)]
struct RouteRef {
    key: Key,
    registration_line: usize,
    clause: Clause,
}
#[derive(Clone, Default)]
struct State {
    locals: BTreeMap<String, Vec<RouteRef>>,
    clause: Clause,
}
struct Compiler {
    functions: BTreeMap<String, (String, syn::ItemFn)>,
    aliases: BTreeMap<String, String>,
    definitions: BTreeMap<Key, Value>,
    visiting: BTreeSet<String>,
    visited: BTreeSet<String>,
}
fn combine(left: &Clause, right: &Clause) -> Option<Clause> {
    let mut clause = left.clone();
    for (key, value) in right {
        if clause.get(key).is_some_and(|existing| existing != value) {
            return None;
        }
        clause.insert(key.clone(), *value);
    }
    Some(clause)
}
fn variable(expr: &syn::Expr) -> Result<String> {
    match expr {
        syn::Expr::Path(p) if p.path.segments.len() == 1 => {
            Ok(p.path.segments[0].ident.to_string())
        }
        syn::Expr::Reference(r) => variable(&r.expr),
        _ => Err(format!(
            "unsupported route-vector lvalue: {}",
            spelling(expr)
        )),
    }
}
impl Compiler {
    fn resolve(&self, source: &str, path: &syn::Path) -> Result<String> {
        let path = spelling(path);
        let mut resolved = if path.starts_with("crate::") {
            path
        } else if let Some(path) = path.strip_prefix("self::") {
            format!("{}::{path}", module(source))
        } else if let Some(path) = path.strip_prefix("super::") {
            format!(
                "{}::{path}",
                module(source)
                    .rsplit_once("::")
                    .ok_or("super outside module")?
                    .0
            )
        } else {
            format!("{}::{path}", module(source))
        };
        let mut seen = BTreeSet::new();
        while let Some(target) = self.aliases.get(&resolved) {
            if !seen.insert(resolved.clone()) {
                return Err("cyclic import alias".into());
            }
            resolved = if target.starts_with("crate::") {
                target.clone()
            } else {
                break;
            };
        }
        if self.functions.contains_key(&resolved) {
            Ok(resolved)
        } else {
            Err(format!("unresolved route factory {resolved}"))
        }
    }
    fn factory(&mut self, name: &str) -> Result<Vec<RouteRef>> {
        if !self.visiting.insert(name.into()) {
            return Err(format!("cyclic route factories: {name}"));
        }
        self.visited.insert(name.into());
        let (source, function) = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing factory {name}"))?;
        let (_, returns) = self.block(&source, &function.block, vec![State::default()], true)?;
        self.visiting.remove(name);
        Ok(returns)
    }
    fn vector(&mut self, source: &str, expr: &syn::Expr, state: &State) -> Result<Vec<RouteRef>> {
        let result = match expr {
            syn::Expr::Macro(m)
                if m.mac.path.is_ident("routes") || m.mac.path.is_ident("catchers") =>
            {
                let paths = Punctuated::<syn::Path, Token![,]>::parse_terminated
                    .parse2(m.mac.tokens.clone())
                    .map_err(|e| e.to_string())?;
                paths
                    .into_iter()
                    .map(|path| {
                        if path.segments.len() != 1 {
                            return Err(
                                "qualified route handler requires explicit resolution".into()
                            );
                        }
                        let key = (source.into(), path.segments[0].ident.to_string());
                        if !self.definitions.contains_key(&key) {
                            return Err(format!("unresolved registered handler {key:?}"));
                        }
                        Ok(RouteRef {
                            key,
                            registration_line: m.mac.span().start().line,
                            clause: Clause::new(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            syn::Expr::Call(call) => {
                if !call.args.is_empty() {
                    return Err("route factory with arguments".into());
                }
                let syn::Expr::Path(path) = &*call.func else {
                    return Err("non-path route factory".into());
                };
                if spelling(&path.path) == "Vec::new" {
                    Vec::new()
                } else {
                    self.factory(&self.resolve(source, &path.path)?)?
                }
            }
            syn::Expr::Path(_) => state
                .locals
                .get(&variable(expr)?)
                .cloned()
                .ok_or("unknown route vector")?,
            syn::Expr::Reference(r) => return self.vector(source, &r.expr, state),
            syn::Expr::Paren(p) => return self.vector(source, &p.expr, state),
            _ => {
                return Err(format!(
                    "unsupported route-vector expression at {source}:{}: {}",
                    expr.span().start().line,
                    spelling(expr)
                ))
            }
        };
        Ok(result
            .into_iter()
            .filter_map(|mut route| {
                route.clause = combine(&route.clause, &state.clause)?;
                Some(route)
            })
            .collect())
    }
    fn block(
        &mut self,
        source: &str,
        block: &syn::Block,
        mut states: Vec<State>,
        tail_returns: bool,
    ) -> Result<(Vec<State>, Vec<RouteRef>)> {
        let mut returned = Vec::new();
        for (index, statement) in block.stmts.iter().enumerate() {
            let tail = tail_returns && index + 1 == block.stmts.len();
            let mut next = Vec::new();
            for mut state in states {
                match statement {
                    syn::Stmt::Local(local) => {
                        if !local.attrs.is_empty() {
                            return Err("unsupported attributes on route local".into());
                        }
                        let syn::Pat::Ident(ident) = &local.pat else {
                            return Err("unsupported route-vector pattern".into());
                        };
                        let value = self.vector(
                            source,
                            &local
                                .init
                                .as_ref()
                                .ok_or("uninitialized route vector")?
                                .expr,
                            &state,
                        )?;
                        state.locals.insert(ident.ident.to_string(), value);
                        next.push(state);
                    }
                    syn::Stmt::Expr(syn::Expr::If(branch), _) => {
                        let mut active = vec![state];
                        for attribute in &branch.attrs {
                            if !attribute.path().is_ident("cfg") {
                                return Err("unsupported conditional attribute".into());
                            }
                            let guard = spelling(&attribute.meta);
                            let mut expanded = Vec::new();
                            for mut present in active {
                                let mut absent = present.clone();
                                absent.clause.insert(guard.clone(), false);
                                next.push(absent);
                                present.clause.insert(guard.clone(), true);
                                expanded.push(present);
                            }
                            active = expanded;
                        }
                        for mut yes in active {
                            let condition = spelling(&branch.cond);
                            let mut no = yes.clone();
                            yes.clause.insert(condition.clone(), true);
                            no.clause.insert(condition, false);
                            let (pending, results) =
                                self.block(source, &branch.then_branch, vec![yes], tail)?;
                            next.extend(pending);
                            returned.extend(results);
                            if let Some((_, otherwise)) = &branch.else_branch {
                                let syn::Expr::Block(otherwise) = &**otherwise else {
                                    return Err("unsupported else-if in route factory".into());
                                };
                                let (pending, results) =
                                    self.block(source, &otherwise.block, vec![no], tail)?;
                                next.extend(pending);
                                returned.extend(results);
                            } else if tail {
                                return Err("non-returning final branch".into());
                            } else {
                                next.push(no);
                            }
                        }
                    }
                    syn::Stmt::Expr(syn::Expr::Return(ret), _) => returned.extend(self.vector(
                        source,
                        ret.expr.as_deref().ok_or("empty return")?,
                        &state,
                    )?),
                    syn::Stmt::Expr(syn::Expr::MethodCall(call), _) if call.method == "append" => {
                        if call.args.len() != 1 {
                            return Err("append argument count".into());
                        }
                        let target = variable(&call.receiver)?;
                        let arg = call.args.first().unwrap();
                        let value = self.vector(source, arg, &state)?;
                        if let Ok(donor) = variable(arg) {
                            state
                                .locals
                                .get_mut(&donor)
                                .ok_or("unknown append donor")?
                                .clear();
                        }
                        state
                            .locals
                            .get_mut(&target)
                            .ok_or("unknown append target")?
                            .extend(value);
                        next.push(state);
                    }
                    syn::Stmt::Expr(expr, None) if tail => {
                        returned.extend(self.vector(source, expr, &state)?)
                    }
                    syn::Stmt::Macro(m)
                        if ["info", "debug", "warn"]
                            .iter()
                            .any(|p| m.mac.path.is_ident(p)) =>
                    {
                        next.push(state)
                    }
                    _ => {
                        return Err(format!(
                            "unsupported factory statement at {source}:{}: {}",
                            statement.span().start().line,
                            spelling(statement)
                        ))
                    }
                }
            }
            states = next;
        }
        if tail_returns && !states.is_empty() {
            return Err(format!("factory has unreturned execution path in {source}"));
        }
        Ok((states, returned))
    }
}

fn minimize(mut clauses: BTreeSet<Clause>) -> Vec<Clause> {
    loop {
        let mut additions = BTreeSet::new();
        let all = clauses.iter().collect::<Vec<_>>();
        for (index, left) in all.iter().enumerate() {
            for right in all.iter().skip(index + 1) {
                if left.len() != right.len() || left.keys().ne(right.keys()) {
                    continue;
                }
                let changed = left
                    .iter()
                    .filter(|(k, v)| right.get(*k) != Some(*v))
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>();
                if changed.len() == 1 {
                    let mut simpler = (*left).clone();
                    simpler.remove(changed[0]);
                    additions.insert(simpler);
                }
            }
        }
        let before = clauses.clone();
        clauses.extend(additions);
        let all = clauses.clone();
        clauses.retain(|c| {
            !all.iter()
                .any(|a| a.len() < c.len() && a.iter().all(|(k, v)| c.get(k) == Some(v)))
        });
        if clauses == before {
            return clauses.into_iter().collect();
        }
    }
}

fn family(source: &str, path: &str) -> &'static str {
    if source == "src/api/admin.rs" {
        return "admin";
    }
    if source == "src/api/identity.rs" {
        return "identity";
    }
    if source == "src/api/icons.rs" {
        return "icons";
    }
    if source == "src/api/notifications.rs" {
        return "notifications";
    }
    if path.contains("/attachment") {
        return "attachments";
    }
    if source == "src/api/web.rs" {
        return "web";
    }
    if source.contains("/two_factor/") {
        return "two_factor";
    }
    if path.contains("/collections") {
        return "collections";
    }
    if path.contains("/groups") {
        return "groups";
    }
    if path.contains("/policies") {
        return "policies";
    }
    if source.ends_with("/events.rs") {
        return "events";
    }
    if path.starts_with("/api/devices") {
        return "devices";
    }
    if path.starts_with("/api/auth-requests") {
        return "auth_requests";
    }
    if path == "/api/tasks" {
        return "tasks";
    }
    if source.ends_with("/accounts.rs") {
        return "accounts";
    }
    if source.ends_with("/organizations.rs") {
        return "organizations";
    }
    if source.ends_with("/ciphers.rs") {
        return "ciphers";
    }
    if source.ends_with("/folders.rs") {
        return "folders";
    }
    if source.ends_with("/sends.rs") {
        return "sends";
    }
    if source.ends_with("/emergency_access.rs") {
        return "emergency_access";
    }
    if source.ends_with("/public.rs") {
        return "public";
    }
    "core"
}

pub fn build(root: &Path, sha: &str, ast: &Value) -> Result<Value> {
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid source commit SHA".into());
    }
    if !ast["errors"]
        .as_array()
        .ok_or("missing AST errors")?
        .is_empty()
    {
        return Err("AST extraction errors".into());
    }
    if !ast["dynamic_route_constructors"]
        .as_array()
        .ok_or("missing dynamic constructor scan")?
        .is_empty()
    {
        return Err("dynamic Rocket route constructors require explicit support".into());
    }
    let mut compiler = Compiler {
        functions: BTreeMap::new(),
        aliases: BTreeMap::new(),
        definitions: BTreeMap::new(),
        visiting: BTreeSet::new(),
        visited: BTreeSet::new(),
    };
    let mut hashes = BTreeMap::new();
    for path in source_files(&root.join("src"))? {
        let source = path.strip_prefix(root).unwrap().display().to_string();
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        hashes.insert(source.clone(), format!("{:x}", Sha256::digest(&bytes)));
        let parsed = syn::parse_file(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        for item in parsed.items {
            match item {
                syn::Item::Fn(function) => {
                    compiler.functions.insert(
                        format!("{}::{}", module(&source), function.sig.ident),
                        (source.clone(), function),
                    );
                }
                syn::Item::Use(import) => {
                    uses(&import.tree, "", &mut compiler.aliases, &module(&source))
                }
                _ => {}
            }
        }
    }
    for definition in ast["definitions"].as_array().ok_or("missing definitions")? {
        let key = (
            text(&definition["source"]).into(),
            text(&definition["handler"]).into(),
        );
        if compiler
            .definitions
            .insert(key, definition.clone())
            .is_some()
        {
            return Err("multiple route attributes on one handler require support".into());
        }
    }
    let mut routes = Vec::new();
    let mut catchers = Vec::new();
    let mut mounts = Vec::new();
    let mut used = BTreeSet::new();
    let mut all_mounts = ast["mounts"].as_array().ok_or("missing mounts")?.clone();
    all_mounts.sort_by_key(|m| m["line"].as_u64());
    for mount in all_mounts {
        if mount["source"] != "src/main.rs"
            || mount["function"] != "launch_rocket"
            || mount["conditions"] != json!([])
        {
            return Err("unexpected mount outside reviewed launch_rocket".into());
        }
        let base: syn::Expr =
            syn::parse_str(text(&mount["arguments"][0])).map_err(|e| e.to_string())?;
        let syn::Expr::MethodCall(base) = base else {
            return Err("unrecognized basepath expression".into());
        };
        if base.method != "concat" || !base.args.is_empty() {
            return Err("unrecognized mount basepath transform".into());
        }
        let syn::Expr::Array(base) = *base.receiver else {
            return Err("unrecognized mount prefix".into());
        };
        if base.elems.len() != 2 || spelling(&base.elems[0]) != "basepath" {
            return Err("unrecognized domain prefix".into());
        }
        let syn::Expr::Lit(prefix) = &base.elems[1] else {
            return Err("nonliteral mount prefix".into());
        };
        let syn::Lit::Str(prefix) = &prefix.lit else {
            return Err("nonstring mount prefix".into());
        };
        let prefix = prefix.value();
        let factory: syn::Expr =
            syn::parse_str(text(&mount["arguments"][1])).map_err(|e| e.to_string())?;
        let syn::Expr::Call(factory) = factory else {
            return Err("noncall mounted factory".into());
        };
        if !factory.args.is_empty() {
            return Err("mounted factory takes arguments".into());
        }
        let syn::Expr::Path(factory) = *factory.func else {
            return Err("nonpath mounted factory".into());
        };
        let resolved = compiler.resolve("src/main.rs", &factory.path)?;
        let references = compiler.factory(&resolved)?;
        let mut by_key = BTreeMap::<Key, (usize, BTreeSet<Clause>)>::new();
        for route in references {
            let item = by_key
                .entry(route.key)
                .or_insert((route.registration_line, BTreeSet::new()));
            if item.0 != route.registration_line {
                return Err("same handler registered by distinct macros".into());
            }
            item.1.insert(route.clause);
        }
        mounts.push(
            json!({"kind":mount["kind"],"prefix":prefix,"factory":resolved,"line":mount["line"]}),
        );
        for (key, (registration_line, conditions)) in by_key {
            if !used.insert(key.clone()) {
                return Err(format!("route handler mounted multiple times: {key:?}"));
            }
            let definition = &compiler.definitions[&key];
            let conditions = minimize(conditions)
                .into_iter()
                .map(|c| {
                    c.into_iter()
                        .map(|(condition, value)| {
                            if value {
                                condition
                            } else {
                                format!("!({condition})")
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut row = json!({"handler":key.1,"source":key.0,"line":definition["attribute_line"],"registration_line":registration_line,"conditions_any_of":conditions,"mount":prefix});
            if definition["kind"] == "catch" {
                if mount["kind"] != "register" {
                    return Err("catcher mounted as route".into());
                }
                row["status"] = definition["positional"][0].clone();
                catchers.push(row);
            } else {
                if mount["kind"] != "mount" {
                    return Err("route registered as catcher".into());
                }
                let method = text(&definition["kind"]).to_ascii_uppercase();
                if method == "ROUTE" {
                    return Err("generic route attribute requires explicit method support".into());
                }
                let uri = text(&definition["positional"][0]);
                let joined = mounted_uri(&prefix, uri);
                row["method"] = json!(method);
                row["uri"] = json!(joined);
                row["relative_uri"] = json!(uri);
                row["family"] = json!(family(&key.0, &joined));
                row["rank"] = definition["options"]["rank"].clone();
                row["format"] = definition["options"]["format"].clone();
                row["data"] = definition["options"]["data"].clone();
                for option in definition["options"].as_object().unwrap().keys() {
                    if !["rank", "format", "data"].contains(&option.as_str()) {
                        return Err(format!("unsupported route option {option}"));
                    }
                }
                if !definition["conditions"].as_array().unwrap().is_empty() {
                    row["handler_cfg"] = definition["conditions"].clone();
                }
                routes.push(row);
            }
        }
    }
    let unused = compiler
        .definitions
        .keys()
        .filter(|key| !used.contains(*key))
        .collect::<Vec<_>>();
    if !unused.is_empty() {
        return Err(format!(
            "unregistered or unreachable route attributes: {unused:?}"
        ));
    }
    let macros = ast["route_macros"].as_array().ok_or("missing macros")?;
    for mac in macros {
        let identity = format!(
            "{}::{}",
            module(text(&mac["source"])),
            text(&mac["function"])
        );
        if !compiler.visited.contains(&identity) {
            return Err(format!("unreachable routes!/catchers! factory {identity}"));
        }
    }
    routes.sort_by_key(|r| {
        (
            text(&r["uri"]).to_owned(),
            text(&r["method"]).to_owned(),
            text(&r["source"]).to_owned(),
            text(&r["handler"]).to_owned(),
        )
    });
    catchers.sort_by_key(|r| (text(&r["mount"]).to_owned(), r["status"].as_u64()));
    let mut counts = BTreeMap::<String, usize>::new();
    let mut methods = BTreeMap::<String, usize>::new();
    let mut modules = BTreeMap::<String, usize>::new();
    let mut method_paths = BTreeSet::new();
    let mut method_uris = BTreeSet::new();
    for route in &routes {
        *counts.entry(text(&route["family"]).into()).or_default() += 1;
        *methods.entry(text(&route["method"]).into()).or_default() += 1;
        *modules.entry(text(&route["source"]).into()).or_default() += 1;
        method_paths.insert((
            text(&route["method"]),
            text(&route["uri"]).split('?').next().unwrap(),
        ));
        method_uris.insert((text(&route["method"]), text(&route["uri"])));
    }
    Ok(
        json!({"schema_version":1,"upstream":{"repository":"https://github.com/dani-garcia/vaultwarden","ref":"main","sha":sha,"source_file_sha256":hashes},"interpretation":{"count":"Union of declared route handlers across build/config variants, not simultaneous distinct HTTP endpoints.","basepath":"All mounts are additionally prefixed by CONFIG.domain_path(). Listed URIs use an empty domain path; mount/relative_uri preserve the exact declarations.","conditions":"conditions_any_of is disjunctive normal form: any inner list may hold, and all expressions within that list must hold. [[]] means unconditional.","rank":"null means Rocket derives its default rank from the path/query; numeric values are explicit.","aliases":"Every registered alias is retained as a separate handler. Identical method/path can differ by query, rank or registration condition.","family":"family is a derived organizational label; by_source_module records the unambiguous upstream source-module counts.","implicit_framework_behavior":"Automatic HEAD fallback for GET and CORS fairing OPTIONS are framework behavior, not extra declared route handlers."},"counts":{"route_handlers":routes.len(),"catchers":catchers.len(),"mounts":mounts.iter().filter(|m|m["kind"]=="mount").count(),"unique_method_uri_templates":method_uris.len(),"unique_method_path_templates":method_paths.len(),"by_family":counts,"by_method":methods,"by_source_module":modules},"mounts":mounts,"routes":routes,"catchers":catchers,"cross_check":{"route_attributes":compiler.definitions.len()-catchers.len(),"catch_attributes":catchers.len(),"registered_handlers":used.len(),"unregistered_attributes":0,"unresolved_registered_handlers":0,"unreachable_registration_factories":0,"dynamic_route_constructors_seen":0}}),
    )
}

pub fn render(value: &Value) -> Result<String> {
    let mut output = String::from("{\n");
    let object = value.as_object().ok_or("inventory must be an object")?;
    for (index, (key, value)) in object.iter().enumerate() {
        if index > 0 {
            output.push_str(",\n");
        }
        output.push_str(&format!("  {}: ", serde_json::to_string(key).unwrap()));
        if ["routes", "catchers", "mounts"].contains(&key.as_str()) {
            output.push('[');
            for (index, row) in value
                .as_array()
                .ok_or("route metadata must be an array")?
                .iter()
                .enumerate()
            {
                if index > 0 {
                    output.push(',');
                }
                output.push_str("\n    ");
                output.push_str(&serde_json::to_string(row).map_err(|e| e.to_string())?);
            }
            output.push_str("\n  ]");
        } else {
            let pretty = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
            output.push_str(&pretty.replace('\n', "\n  "));
        }
    }
    output.push_str("\n}\n");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(factory: &str) -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/test-fixtures")
                .join(format!(
                    "{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir_all(path.join("src/api")).unwrap();
            fs::write(path.join("src/main.rs"),r#"fn launch_rocket() { let basepath=""; rocket::build().mount([basepath,"/api"].concat(),api::test_routes()); }"#).unwrap();
            fs::write(
                path.join("src/api/mod.rs"),
                "pub use crate::api::test::routes as test_routes;",
            )
            .unwrap();
            fs::write(path.join("src/api/test.rs"), factory).unwrap();
            Self(path)
        }
        fn inventory(&self) -> Result<Value> {
            let mut extractor = crate::Extractor::default();
            crate::walk(&self.0, &self.0.join("src"), &mut extractor);
            let ast = json!({"definitions":extractor.definitions,"route_macros":extractor.macros,"factory_calls":extractor.calls,"mounts":extractor.mounts,"dynamic_route_constructors":extractor.dynamic_routes,"errors":extractor.errors});
            build(&self.0, &"a".repeat(40), &ast)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn mounted_aliases_queries_ranks_and_fallthrough_conditions_are_preserved() {
        let fixture = Fixture::new(
            r#"
            pub fn routes()->Vec<Route> {
                if CONFIG.disabled() { return routes![disabled]; }
                let mut routes=routes![read];
                if CONFIG.write_enabled() { routes.append(&mut routes![write]); }
                routes
            }
            #[get("/thing?<query>",rank=2,format="json")] fn read(){}
            #[put("/thing",data="<body>")] fn write(){}
            #[get("/",rank=3)] fn disabled(){}
        "#,
        );
        let result = fixture.inventory().unwrap();
        assert_eq!(result["counts"]["route_handlers"], 3);
        let routes = result["routes"].as_array().unwrap();
        let read = routes.iter().find(|r| r["handler"] == "read").unwrap();
        assert_eq!(read["uri"], "/api/thing?<query>");
        assert_eq!(read["rank"], 2);
        assert_eq!(read["format"], "json");
        assert_eq!(read["conditions_any_of"], json!([["!(CONFIG.disabled())"]]));
        let write = routes.iter().find(|r| r["handler"] == "write").unwrap();
        assert_eq!(
            write["conditions_any_of"],
            json!([["!(CONFIG.disabled())", "CONFIG.write_enabled()"]])
        );
        assert_eq!(write["data"], "<body>");
    }

    #[test]
    fn attributes_without_reachable_registration_fail_closed() {
        let fixture = Fixture::new(
            "pub fn routes()->Vec<Route>{routes![]} #[get(\"/orphan\")] fn orphan(){}",
        );
        assert!(fixture
            .inventory()
            .unwrap_err()
            .contains("unregistered or unreachable"));
    }

    #[test]
    fn unresolved_registered_handlers_fail_closed() {
        let fixture = Fixture::new("pub fn routes()->Vec<Route>{routes![missing]}");
        assert!(fixture
            .inventory()
            .unwrap_err()
            .contains("unresolved registered handler"));
    }

    #[test]
    fn unknown_vector_mutation_and_dynamic_routes_require_explicit_support() {
        let fixture=Fixture::new("pub fn routes()->Vec<Route>{let mut routes=Vec::new(); routes.extend(routes![read]); routes} #[get(\"/\")] fn read(){}");
        assert!(fixture
            .inventory()
            .unwrap_err()
            .contains("unsupported factory statement"));
        let dynamic=Fixture::new("pub fn routes()->Vec<Route>{let route=Route::new(Method::Get,\"/\",handler);routes![]}");
        assert!(dynamic
            .inventory()
            .unwrap_err()
            .contains("dynamic Rocket route constructors"));
    }

    #[test]
    fn cfg_registration_keeps_always_routes_unconditional() {
        let fixture = Fixture::new(
            r#"
            pub fn routes()->Vec<Route>{
                let mut routes=routes![read];
                #[cfg(debug_assertions)]
                if CONFIG.reload_templates() { routes.append(&mut routes![debug]); }
                routes
            }
            #[get("/")] fn read(){}
            #[cfg(debug_assertions)] #[get("/debug")] fn debug(){}
        "#,
        );
        let result = fixture.inventory().unwrap();
        let routes = result["routes"].as_array().unwrap();
        assert_eq!(
            routes.iter().find(|r| r["handler"] == "read").unwrap()["conditions_any_of"],
            json!([[]])
        );
        assert_eq!(
            routes.iter().find(|r| r["handler"] == "debug").unwrap()["conditions_any_of"],
            json!([["CONFIG.reload_templates()", "cfg(debug_assertions)"]])
        );
    }

    #[test]
    fn implementation_source_drift_changes_facts_even_when_routes_do_not() {
        let fixture =
            Fixture::new("pub fn routes()->Vec<Route>{routes![read]} #[get(\"/\")] fn read(){}");
        let before = fixture.inventory().unwrap();
        let path = fixture.0.join("src/api/test.rs");
        let mut source = fs::read_to_string(&path).unwrap();
        source.push_str("\n// implementation changed\n");
        fs::write(path, source).unwrap();
        let after = fixture.inventory().unwrap();
        assert_eq!(before["routes"], after["routes"]);
        assert_ne!(
            before["upstream"]["source_file_sha256"],
            after["upstream"]["source_file_sha256"]
        );
        assert_eq!(
            serde_json::from_str::<Value>(&render(&after).unwrap()).unwrap(),
            after
        );
    }

    #[test]
    fn rocket_051_mount_roots_are_normalized_without_losing_query() {
        assert_eq!(mounted_uri("/admin", "/"), "/admin");
        assert_eq!(
            mounted_uri("/api/", "/items/<item>?<query..>"),
            "/api/items/<item>?<query..>"
        );
        assert_eq!(mounted_uri("/", "/"), "/");
    }
}
