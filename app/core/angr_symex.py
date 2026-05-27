"""Angr-based symbolic execution helpers for AI-driven path exploration."""

import logging

log = logging.getLogger(__name__)

try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def _format_constraints(state, max_constraints=30):
    """Convert solver constraints to human-readable strings."""
    results = []
    for i, c in enumerate(state.solver.constraints):
        if i >= max_constraints:
            results.append(f"... and {len(state.solver.constraints) - max_constraints} more constraints")
            break
        try:
            results.append(str(c))
        except Exception:
            results.append("(unprintable constraint)")
    return results


def _summarize_state(state, proj):
    """Summarize a simulation state (registers, PC, constraints)."""
    arch = proj.arch
    summary = {"pc": hex(state.addr)}
    regs = {}
    for rname in arch.register_names.values():
        if rname in ("rdi", "rsi", "rdx", "rcx", "r8", "r9",  # x64 args
                     "rax", "rbx", "rsp", "rbp",
                     "ecx", "edx", "eax", "ebx",  # x86 args
                     "r0", "r1", "r2", "r3"):  # ARM args
            try:
                val = getattr(state.regs, rname)
                if val.symbolic:
                    regs[rname] = f"<symbolic: {val}>"
                else:
                    regs[rname] = hex(state.solver.eval(val))
            except Exception:
                pass
    summary["registers"] = regs
    summary["constraints_count"] = len(state.solver.constraints)
    summary["constraints"] = _format_constraints(state, max_constraints=15)
    return summary


def symex_explore_paths(proj, cfg, func_addr, target_addr=None, avoid_addrs=None, max_steps=500):
    """Explore execution paths through a function symbolically.

    Returns a dict with found paths, deadended states, and active states summary.
    """
    if not ANGR_AVAILABLE:
        return {"error": "angr not available"}

    try:
        state = proj.factory.call_state(func_addr)
        simgr = proj.factory.simgr(state)

        find = target_addr if target_addr else None
        avoid = avoid_addrs if avoid_addrs else None

        simgr.explore(find=find, avoid=avoid, n=max_steps)

        result = {
            "function_addr": hex(func_addr),
            "steps_taken": max_steps,
            "found_count": len(simgr.found) if hasattr(simgr, 'found') and simgr.found else 0,
            "deadended_count": len(simgr.deadended) if simgr.deadended else 0,
            "active_count": len(simgr.active) if simgr.active else 0,
        }

        if target_addr:
            result["target"] = hex(target_addr)

        found_paths = []
        for i, s in enumerate(simgr.found[:5] if hasattr(simgr, 'found') and simgr.found else []):
            found_paths.append({
                "path_index": i,
                "final_pc": hex(s.addr),
                "history_length": s.history.depth,
                "state": _summarize_state(s, proj),
            })
        result["found_paths"] = found_paths

        if not found_paths and simgr.deadended:
            dead_summaries = []
            for i, s in enumerate(simgr.deadended[:3]):
                dead_summaries.append({
                    "path_index": i,
                    "final_pc": hex(s.addr),
                    "history_length": s.history.depth,
                    "state": _summarize_state(s, proj),
                })
            result["deadended_samples"] = dead_summaries

        if not found_paths and not simgr.deadended and simgr.active:
            active_summaries = []
            for i, s in enumerate(simgr.active[:3]):
                active_summaries.append({
                    "path_index": i,
                    "current_pc": hex(s.addr),
                    "history_length": s.history.depth,
                })
            result["active_samples"] = active_summaries

        return result

    except Exception as e:
        log.exception("symex_explore_paths failed for %#x", func_addr)
        return {"error": str(e)}


def symex_get_constraints(proj, cfg, func_addr, target_addr, max_steps=500):
    """Find what constraints must hold for execution to reach target_addr from func_addr.

    Returns human-readable constraint strings.
    """
    if not ANGR_AVAILABLE:
        return {"error": "angr not available"}

    try:
        state = proj.factory.call_state(func_addr)
        simgr = proj.factory.simgr(state)

        simgr.explore(find=target_addr, n=max_steps)

        if not simgr.found:
            return {
                "function_addr": hex(func_addr),
                "target_addr": hex(target_addr),
                "reachable": False,
                "message": f"Could not reach {hex(target_addr)} from {hex(func_addr)} within {max_steps} steps. "
                           f"Deadended: {len(simgr.deadended)}, Active: {len(simgr.active)}",
            }

        best = min(simgr.found, key=lambda s: len(s.solver.constraints))

        constraints = _format_constraints(best, max_constraints=30)

        arg_values = {}
        for rname in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
            try:
                init_val = best.history.actions.hardcopy[0] if best.history.actions else None
            except Exception:
                init_val = None

        return {
            "function_addr": hex(func_addr),
            "target_addr": hex(target_addr),
            "reachable": True,
            "path_length": best.history.depth,
            "constraint_count": len(best.solver.constraints),
            "constraints": constraints,
            "state_at_target": _summarize_state(best, proj),
        }

    except Exception as e:
        log.exception("symex_get_constraints failed")
        return {"error": str(e)}


def symex_inspect_state(proj, func_addr, arg_values=None, steps=50):
    """Step through a function and inspect state after N steps.

    arg_values: dict of register_name -> hex_value for concrete args.
    If a register is not provided, it remains symbolic.
    """
    if not ANGR_AVAILABLE:
        return {"error": "angr not available"}

    try:
        state = proj.factory.call_state(func_addr)

        if arg_values:
            for reg, val in arg_values.items():
                if isinstance(val, str):
                    val = int(val, 16) if val.startswith("0x") else int(val)
                try:
                    setattr(state.regs, reg, val)
                except Exception as e:
                    log.warning("Could not set register %s: %s", reg, e)

        simgr = proj.factory.simgr(state)
        simgr.step(n=steps)

        result = {
            "function_addr": hex(func_addr),
            "steps_requested": steps,
            "active_states": len(simgr.active),
            "deadended_states": len(simgr.deadended),
        }

        states = []
        for i, s in enumerate(simgr.active[:5]):
            states.append({
                "index": i,
                "type": "active",
                **_summarize_state(s, proj),
            })
        for i, s in enumerate(simgr.deadended[:3]):
            states.append({
                "index": i,
                "type": "deadended",
                **_summarize_state(s, proj),
            })

        result["states"] = states
        return result

    except Exception as e:
        log.exception("symex_inspect_state failed")
        return {"error": str(e)}
