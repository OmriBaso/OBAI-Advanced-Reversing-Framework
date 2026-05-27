import logging

log = logging.getLogger(__name__)

ANGR_AVAILABLE = False
try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    pass


def angr_create_project(binary_path):
    if not ANGR_AVAILABLE:
        return None
    try:
        return angr.Project(binary_path, load_options={"auto_load_libs": False})
    except Exception as e:
        log.warning("angr project creation failed: %s", e)
        return None


def angr_run_cfg(proj):
    if not proj:
        return None
    try:
        return proj.analyses.CFGFast(normalize=True, show_progressbar=False)
    except Exception as e:
        log.warning("angr CFGFast failed: %s", e)
        return None


def angr_get_cfg_data(proj, cfg, func_addr):
    """Build CFG graph data for Cytoscape.js from angr."""
    if not proj or not cfg:
        return {"nodes": [], "edges": []}

    func = cfg.kb.functions.get(func_addr)
    if not func or not func.graph:
        return {"nodes": [], "edges": []}

    nodes, edges = [], []
    graph = func.graph

    for node in graph.nodes():
        label_lines = [f"{node.addr:#x}"]
        try:
            block = proj.factory.block(node.addr, size=node.size)
            if block.capstone:
                for insn in list(block.capstone.insns)[:6]:
                    label_lines.append(f"{insn.mnemonic} {insn.op_str}")
                if len(list(block.capstone.insns)) > 6:
                    label_lines.append("...")
        except Exception:
            label_lines.append("(unreadable)")

        node_type = "normal"
        if node.addr == func.addr:
            node_type = "entry"
        successors = list(graph.successors(node))
        if len(successors) > 1:
            node_type = "branch"
        if len(successors) == 0:
            node_type = "exit"
        try:
            block = proj.factory.block(node.addr, size=node.size)
            if block.capstone:
                last = list(block.capstone.insns)[-1]
                if last.mnemonic == "call":
                    node_type = "call"
        except Exception:
            pass

        nodes.append({"data": {"id": hex(node.addr), "label": "\n".join(label_lines), "type": node_type}})

    for src, dst in graph.edges():
        edges.append({"data": {"source": hex(src.addr), "target": hex(dst.addr)}})

    return {"nodes": nodes, "edges": edges}


def angr_get_call_chain(sess, db, root_name, direction="backward", max_depth=8, max_nodes=300):
    """BFS over the angr callgraph from a root function.

    direction="backward" walks caller→callee edges in reverse (predecessors of root),
    producing the upstream call tree — useful for sink/data-flow analysis.
    direction="forward" walks callees.

    Returns Cytoscape-style {nodes, edges, root, depth_reached, truncated}.
    """
    if not sess.angr_cfg:
        return None, "angr CFG not available"

    from .helpers import addr_str_to_int, find_func_addr, build_addr_to_name_map, resolve_angr_func_addr

    root_addr = resolve_angr_func_addr(sess, db, root_name)
    if root_addr is None:
        root_addr = addr_str_to_int(find_func_addr(db, root_name))
    if root_addr is None:
        return None, f"Function '{root_name}' not found"

    cg = sess.angr_cfg.kb.callgraph
    if root_addr not in cg:
        for a in cg.nodes():
            if abs(a - root_addr) <= 16:
                root_addr = a
                break
        else:
            return None, f"Function '{root_name}' not in call graph"

    kb = sess.angr_cfg.kb.functions
    name_map = build_addr_to_name_map(db)

    def node_for(addr, is_root=False):
        f = kb.get(addr)
        name = name_map.get(addr) or (f.name if f else f"sub_{addr:x}")
        is_import = bool(f and (f.is_simprocedure or f.is_plt)) if f else False
        return {
            "data": {
                "id": hex(addr),
                "label": name,
                "name": name,
                "address_hex": hex(addr),
                "is_root": is_root,
                "is_import": is_import,
            }
        }

    nodes = [node_for(root_addr, is_root=True)]
    edges = []
    seen_nodes = {root_addr}
    seen_edges = set()
    frontier = [(root_addr, 0)]
    depth_reached = 0
    truncated = False

    while frontier and not truncated:
        addr, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        neighbors = cg.predecessors(addr) if direction == "backward" else cg.successors(addr)
        for n in neighbors:
            if direction == "backward":
                edge_key = (n, addr)
                src, dst = hex(n), hex(addr)
            else:
                edge_key = (addr, n)
                src, dst = hex(addr), hex(n)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            edges.append({"data": {"source": src, "target": dst}})

            if n not in seen_nodes:
                if len(nodes) >= max_nodes:
                    truncated = True
                    break
                seen_nodes.add(n)
                nodes.append(node_for(n))
                frontier.append((n, depth + 1))
                if depth + 1 > depth_reached:
                    depth_reached = depth + 1

    return {
        "nodes": nodes,
        "edges": edges,
        "root": hex(root_addr),
        "depth_reached": depth_reached,
        "truncated": truncated,
        "direction": direction,
    }, None


def angr_call_chain_text(sess, db, root_name, max_depth=8, max_nodes=300, max_paths=10):
    """Format the backward call chain as readable text for AI consumption."""
    data, error = angr_get_call_chain(
        sess, db, root_name, direction="backward", max_depth=max_depth, max_nodes=max_nodes
    )
    if error:
        return None, error

    import networkx as nx

    g = nx.DiGraph()
    name_by_id = {}
    for n in data["nodes"]:
        nid = n["data"]["id"]
        g.add_node(nid)
        name_by_id[nid] = n["data"]["name"]
    for e in data["edges"]:
        g.add_edge(e["data"]["source"], e["data"]["target"])

    root_id = data["root"]
    direct = list(g.predecessors(root_id))
    entries = [n for n in g.nodes() if n != root_id and g.in_degree(n) == 0]

    sample_paths = []
    for entry in entries:
        try:
            for p in nx.all_simple_paths(g, entry, root_id, cutoff=max_depth + 1):
                sample_paths.append(p)
                break  # one representative per entry
        except Exception:
            pass
        if len(sample_paths) >= max_paths:
            break

    note = ""
    if data["truncated"]:
        if data["depth_reached"] >= max_depth:
            note = f" — stopped at layer cap (max_layers={max_depth}); raise it to see more"
        else:
            note = " — hit internal node-count safety cap (binary is enormous)"
    lines = [
        f"Backward call chain from {root_name} ({root_id}):",
        f"  Total upstream functions: {len(data['nodes']) - 1}, layers reached {data['depth_reached']}" + note,
        "  (Each layer = one call-graph hop. All sibling callers within a layer are always returned together.)",
    ]

    if direct:
        lines.append(f"\nDirect callers ({len(direct)}):")
        for nid in direct[:30]:
            lines.append(f"  - {name_by_id[nid]} ({nid})")
        if len(direct) > 30:
            lines.append(f"  ... +{len(direct) - 30} more")

    if entries:
        lines.append(f"\nUpstream entry points ({len(entries)} — no further callers in graph):")
        for nid in entries[:30]:
            lines.append(f"  - {name_by_id[nid]} ({nid})")
        if len(entries) > 30:
            lines.append(f"  ... +{len(entries) - 30} more")

    if sample_paths:
        lines.append(f"\nSample paths to {root_name}:")
        for i, p in enumerate(sample_paths, 1):
            chain_str = " -> ".join(name_by_id[n] for n in p)
            lines.append(f"  {i}. {chain_str}")

    if not direct and not entries:
        lines.append("\nNo callers found in the binary's call graph.")

    return "\n".join(lines), None


def angr_find_call_path(sess, db, source_name, target_name):
    """Find the shortest call path between two functions using angr's call graph."""
    if not sess.angr_cfg:
        return None, "angr CFG not available"

    import networkx as nx
    from .helpers import addr_str_to_int, find_func_addr, build_addr_to_name_map

    src_addr = addr_str_to_int(find_func_addr(db, source_name))
    tgt_addr = addr_str_to_int(find_func_addr(db, target_name))

    if src_addr is None:
        return None, f"Source function '{source_name}' not found"
    if tgt_addr is None:
        return None, f"Target function '{target_name}' not found"

    cg = sess.angr_cfg.kb.callgraph
    kb = sess.angr_cfg.kb.functions

    src_match = src_addr if src_addr in cg else None
    tgt_match = tgt_addr if tgt_addr in cg else None
    if not src_match:
        for a in cg.nodes():
            if abs(a - src_addr) <= 16:
                src_match = a
                break
    if not tgt_match:
        for a in cg.nodes():
            if abs(a - tgt_addr) <= 16:
                tgt_match = a
                break

    if not src_match or not tgt_match:
        return None, "One or both functions not found in call graph"

    try:
        path_addrs = nx.shortest_path(cg, src_match, tgt_match)
    except nx.NetworkXNoPath:
        return None, f"No call path from {source_name} to {target_name}"
    except nx.NodeNotFound as e:
        return None, f"Node not in graph: {e}"

    name_map = build_addr_to_name_map(db)
    path_names = []
    for addr in path_addrs:
        f = kb.get(addr)
        name = name_map.get(addr) or (f.name if f else f"sub_{addr:x}")
        path_names.append({"name": name, "address_hex": hex(addr)})

    return path_names, None


def angr_get_cfg_text(sess, db, func_name):
    """Serialize a function's CFG as structured text the AI can reason about."""
    if not sess.angr_project or not sess.angr_cfg:
        return None, "angr CFG not available"

    from .helpers import addr_str_to_int, find_func_addr

    func_addr = addr_str_to_int(find_func_addr(db, func_name))
    if func_addr is None:
        return None, f"Function '{func_name}' not found"

    func = sess.angr_cfg.kb.functions.get(func_addr)
    if not func:
        for a, f in sess.angr_cfg.kb.functions.items():
            if abs(a - func_addr) <= 16:
                func = f
                break
    if not func or not func.graph:
        return None, f"No CFG available for '{func_name}'"

    graph = func.graph
    proj = sess.angr_project
    lines = [f"Control Flow Graph for {func_name} ({hex(func.addr)}):"]
    lines.append(f"  Entry block: {hex(func.addr)}")
    lines.append(f"  Total blocks: {len(graph.nodes())}")
    lines.append("")

    for node in sorted(graph.nodes(), key=lambda n: n.addr):
        successors = list(graph.successors(node))
        predecessors = list(graph.predecessors(node))

        block_type = "normal"
        if node.addr == func.addr:
            block_type = "ENTRY"
        elif len(successors) == 0:
            block_type = "EXIT"
        elif len(successors) > 1:
            block_type = "BRANCH"

        lines.append(f"  Block {hex(node.addr)} [{block_type}]:")

        try:
            block = proj.factory.block(node.addr, size=node.size)
            if block.capstone:
                insns = list(block.capstone.insns)
                for insn in insns[:8]:
                    lines.append(f"    {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                if len(insns) > 8:
                    lines.append(f"    ... ({len(insns) - 8} more instructions)")

                last = insns[-1] if insns else None
                if last and last.mnemonic.startswith("j") and len(successors) == 2:
                    lines.append(f"    Condition: {last.mnemonic} {last.op_str}")
                    lines.append(f"      True  -> {hex(successors[0].addr)}")
                    lines.append(f"      False -> {hex(successors[1].addr)}")
                elif successors:
                    for s in successors:
                        lines.append(f"    -> {hex(s.addr)}")
        except Exception:
            lines.append("    (could not disassemble)")
            for s in successors:
                lines.append(f"    -> {hex(s.addr)}")

        if predecessors:
            pred_str = ", ".join(hex(p.addr) for p in predecessors)
            lines.append(f"    Predecessors: {pred_str}")
        lines.append("")

    return "\n".join(lines), None
