import ts from "typescript";

const verbs = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
export const requestKey = row => JSON.stringify([row.source.path, row.source.start, row.source.end, row.transport, row.method, row.template]);
export const referenceKey = row => JSON.stringify([row.path, row.line, row.name, row.receiver, row.function]);
export const genericKey = row => JSON.stringify([row.kind, row.source.path, row.source.line, row.expression]);
export const commandKey = row => JSON.stringify([row.declaration, row.source.path, row.source.line, row.source.start, row.source.end, row.registration ?? null]);

// This discovers syntax, not a typed call graph or runtime reachability.
export function discoverRequests(sources) {
  const requests = [], generic = [], references = [], commands = [];
  function context(node) {
    for (let parent = node; parent; parent = parent.parent) {
      if (ts.isMethodDeclaration(parent) || ts.isFunctionDeclaration(parent) || ts.isConstructorDeclaration(parent) || ts.isGetAccessorDeclaration(parent)) return parent;
      if (ts.isClassDeclaration(parent)) break;
    }
    return undefined;
  }
  for (const [path, text] of sources) {
    if (!path.endsWith(".ts") || path.startsWith("node_modules/")) continue;
    const sf = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    if (sf.parseDiagnostics.length) throw Error(`Cannot parse shipped source ${path}`);
    const nodes = [];
    function visit(node) { nodes.push(node); ts.forEachChild(node, visit); }
    visit(sf);
    const location = node => ({ path, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, start: node.getStart(sf), end: node.end });
    const unique = values => [...new Set(values)].slice(0, 32);
    const combine = (left, right) => unique(left.flatMap(x => right.map(y => x + y)));
    function evaluate(node, at = node?.getStart(sf), seen = new Set()) {
      if (!node) return ["{unresolved}"];
      if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isAwaitExpression(node)) return evaluate(node.expression, at, seen);
      if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return [node.text];
      if (ts.isTemplateExpression(node)) {
        let result = [node.head.text];
        for (const span of node.templateSpans) result = combine(combine(result, evaluate(span.expression, at, seen)), [span.literal.text]);
        return result;
      }
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return combine(evaluate(node.left, at, seen), evaluate(node.right, at, seen));
      if (ts.isConditionalExpression(node)) return unique([...evaluate(node.whenTrue, at, seen), ...evaluate(node.whenFalse, at, seen)]);
      if (ts.isCallExpression(node)) {
        const name = node.expression.getText(sf);
        for (const [suffix, base] of [[".getApiUrl", "apiBase"], [".getIdentityUrl", "identityBase"], [".getEventsUrl", "eventsBase"]]) if (name.endsWith(suffix)) return [`{${base}}`];
        if (["encodeURI", "encodeURIComponent"].includes(name)) return evaluate(node.arguments[0], at, seen);
        return ["{" + node.getText(sf).replace(/\s+/g, " ") + "}"];
      }
      if (ts.isIdentifier(node)) {
        const key = node.text;
        if (seen.has(key)) return [`{${key}}`];
        const next = new Set(seen).add(key), current = context(node);
        const definitions = nodes.filter(n => ts.isVariableDeclaration(n) && n.name.getText(sf) === key && n.initializer && n.getStart(sf) < at && (context(n) === current || !context(n)));
        const local = definitions.filter(n => context(n) === current);
        const definition = (local.length ? local : definitions).at(-1);
        let result = definition ? evaluate(definition.initializer, definition.getStart(sf), next) : [`{${key}}`];
        if (definition) {
          for (const assignment of nodes.filter(n => ts.isBinaryExpression(n) && n.left.getText(sf) === key && n.getStart(sf) > definition.getStart(sf) && n.getStart(sf) < at && context(n) === current)) {
            if (assignment.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) result = unique([...result, ...combine(result, evaluate(assignment.right, assignment.getStart(sf), next))]);
            if (assignment.operatorToken.kind === ts.SyntaxKind.EqualsToken) result = unique([...result, ...evaluate(assignment.right, assignment.getStart(sf), next)]);
          }
        }
        return result;
      }
      return ["{" + node.getText(sf).replace(/\s+/g, " ") + "}"];
    }
    function optionsMethod(node) {
      if (!node) return ["GET"];
      if (ts.isIdentifier(node)) {
        const definition = nodes.find(n => ts.isVariableDeclaration(n) && n.name.getText(sf) === node.text && n.initializer && context(n) === context(node));
        if (definition) return optionsMethod(definition.initializer);
      }
      if (ts.isObjectLiteralExpression(node)) {
        const method = node.properties.find(n => ts.isPropertyAssignment(n) && n.name.getText(sf) === "method");
        return method ? evaluate(method.initializer) : ["GET"];
      }
      return ["{request.method}"];
    }
    function add(node, methods, urls, transport) {
      for (const method of methods) for (const template of urls) requests.push({ method, template, transport, source: location(node) });
    }
    function unresolved(node, kind) { generic.push({ kind, expression: node.getText(sf), source: location(node) }); }
    function ownerClass(node) {
      for (let parent = node; parent; parent = parent.parent) if (ts.isClassDeclaration(parent)) return parent;
    }
    function addCommand(node, argument, startNode = node) {
      const source = { ...location(startNode), end: node.end };
      if (ts.isStringLiteralLike(argument)) { commands.push({ declaration: argument.text, source }); return; }
      const method = context(node);
      const parameter = method?.parameters?.findIndex(parameter => parameter.name.getText(sf) === argument.getText(sf)) ?? -1;
      if (parameter < 0 || !method.name) throw Error(`Unresolved command declaration at ${path}:${source.line}`);
      const callsites = nodes.filter(call => ts.isCallExpression(call) && ts.isPropertyAccessExpression(call.expression) && call.expression.expression.kind === ts.SyntaxKind.ThisKeyword && call.expression.name.text === method.name.getText(sf) && ownerClass(call) === ownerClass(method));
      if (!callsites.length) throw Error(`No registration calls for ${path}:${source.line}`);
      for (const call of callsites) {
        const value = call.arguments[parameter];
        if (!value || !ts.isStringLiteralLike(value)) throw Error(`Unresolved command registration at ${path}:${location(call).line}`);
        commands.push({ declaration: value.text, source, registration: location(call) });
      }
    }
    for (const node of nodes) {
      if (/^(apps\/cli\/|bitwarden_license\/bit-cli\/)/.test(path)) {
        if (ts.isNewExpression(node) && node.expression.getText(sf) === "Command" && node.arguments?.[0]) addCommand(node, node.arguments[0]);
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "command" && node.arguments[0]) addCommand(node, node.arguments[0], node.expression.name);
      }
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const name = node.expression.name.text, args = node.arguments, func = context(node);
        references.push({ path, line: location(node).line, name, receiver: node.expression.expression.getText(sf), function: func?.name?.getText(sf) ?? (func && ts.isConstructorDeclaration(func) ? "constructor" : "<module>") });
        if (name === "send" && args.length >= 2 && ts.isStringLiteral(args[0]) && verbs.has(args[0].text)) {
          const bases = args[5] && args[5].kind !== ts.SyntaxKind.NullKeyword ? evaluate(args[5]) : ["{apiBase}"];
          add(node, [args[0].text], combine(bases, evaluate(args[1])), "ApiService.send");
        }
        if (name === "createRequest" && args.length >= 1 && !path.includes("abstraction")) {
          const methods = optionsMethod(args[1]);
          if (methods.some(method => verbs.has(method))) add(node, methods, evaluate(args[0]), "HttpOperations.createRequest");
          else unresolved(node, "generic_transport");
        }
        if (/^(get|post|put|patch|delete|all|options|head)$/.test(name) && node.expression.expression.getText(sf) === "router" && args[0] && ts.isStringLiteral(args[0])) add(node, [name.toUpperCase()], [args[0].text], "Koa router");
      }
      if (ts.isNewExpression(node) && node.expression.getText(sf) === "Request") {
        const args = node.arguments ?? [], methods = optionsMethod(args[1]);
        if (methods.some(method => verbs.has(method))) add(node, methods, evaluate(args[0]), "Request construction");
        else unresolved(node, "generic_request");
      }
    }
  }
  return { requests, generic, references, commands };
}
