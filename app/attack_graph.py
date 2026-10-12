
import networkx as nx


def build_attack_graph(events):
    graph = nx.DiGraph()

    # Add each event as a node.
    for event in events:
        event_id = event.get("event_id")

        if not event_id:
            continue

        graph.add_node(
            event_id,
            timestamp=event.get("timestamp"),
            event_type=event.get("event_type"),
            source_ip=event.get("source_ip"),
            username=event.get("username"),
        )

    # Group events by source IP.
    events_by_ip = {}

    for event in events:
        event_id = event.get("event_id")
        source_ip = event.get("source_ip")

        if not event_id or not source_ip:
            continue

        events_by_ip.setdefault(source_ip, []).append(event)

    # Connect consecutive events from the same source IP.
    for source_ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e.get("timestamp", ""))

        for previous, current in zip(ip_events, ip_events[1:]):
            graph.add_edge(
                previous["event_id"],
                current["event_id"],
                relationship="same_source_ip",
                source_ip=source_ip,
                confidence="candidate relationship",
            )

    return {
        "nodes": [
            {"event_id": node, **attributes}
            for node, attributes in graph.nodes(data=True)
        ],
        "edges": [
            {"from": source, "to": target, **attributes}
            for source, target, attributes in graph.edges(data=True)
        ],
        "summary": {
            "event_count": graph.number_of_nodes(),
            "relationship_count": graph.number_of_edges(),
        },
    }
