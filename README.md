"What if your database was in superposition until someone looked at it?"

This is just an idea I've had.  

(CRDT + Merkle DAG) × Gossip → Raft on Read


Uses:


https://github.com/saturnines/lygus

or more seriously.

 does sequential commits over a CRDT Merkle DAG produce prefix-compatible total orders with disjoint subgraphs?

If you commit the DAG at time T and then commit again at time T+1, the two commits operate on completely disjoint sets of nodes, and concatenating their total orders does it produces a valid linearization?
