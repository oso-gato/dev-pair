# 000030 — Both components are tailnet nodes, and each carries its own doors

- status: accepted
- date: 2026-08-18

## Problem

The erebus work gave the host a tailnet address and a public SSH door, and gave the dev-container neither. It was reachable only from the host, and the Quadlet said so in a comment that cited the objective's Security outcome 1 as the reason.

That citation was backwards. Security outcome 1 reads "the only public doors: hardened SSH/MOSH on **both components** of every pair". The dev-container is a component, not one of the "everything else" services the following clause confines to private networks. Building it with no door of its own left one of the two doors the objective requires unbuilt, and the comment claiming otherwise made the defect harder to see rather than easier.

The maintainer caught it, and settled the wider question at the same time: both components are on the tailnet, and Tailscale SSH is enabled on each.

## Decision

Each component of a pair carries its own doors, and there are two kinds.

**A public door.** The host keeps SSH on 22 and mosh on its default range. The dev-container publishes SSH on 4444, mapping to 22 inside, because the host's own sshd already holds 22 on the same address. Its mosh range is 61001-62000, published one-to-one.

Both port choices are load-bearing rather than arbitrary. The mapping must be one-to-one because mosh-server tells the client which port it selected, so a rewritten port breaks the handshake. The range must start above 61000 because mosh's default is 60000-61000 and the host's own mosh uses it — an overlapping publish would collide with the host on the same public address.

**A tailnet door.** Each component joins the tailnet as its own node with its own hostname and its own Tailscale SSH. Two nodes rather than one means the tailnet ACL can grant reach to the dev-container without granting reach to the host that operates it, which is C6's least privilege expressed at the network layer. It also means the dev-container is reachable when the host's own door is not, and the reverse.

Both doors authenticate the same way the rest of the platform does. The public door is keys only, from the same published trust root, with root refused; no password authenticates a remote shell on either component. The tailnet door authenticates by tailnet identity, which is not a password.

The dev-container's tailnet state persists on a mounted volume, so a relaunch rejoins as the same node rather than burning a fresh machine entry on every restart. Its auth key is placed once at genesis, read once at join, and not needed again.

## Options considered

- **Reach the dev-container only through the host.** This is what was built, and it is what the objective forbids. It also has an operational cost the objective's wording anticipates: one door means one failure closes both components.
- **Give the dev-container a tailnet node but no public door.** Rejected — half the requirement. The objective names SSH/MOSH as the public doors on both components, and the maintainer's stated need was mosh directly to the dev-container.
- **Give it a public door but no tailnet node.** Proposed by the author on minimalism grounds, since a public door already satisfies reachability and C3 admits a capability only on a decision. The maintainer decided otherwise, and the reason is sound: two nodes let the ACL separate the two components, which one node cannot.
- **Publish mosh on the default 60000-61000 range.** Rejected. It collides with the host's own mosh on the same address, and the collision would appear as intermittent session failures rather than as a clean error.

## Consequences

The dev-container image gains `openssh-server`, `mosh` and `tailscale`; its init opens both doors and warns loudly when no key is authorized rather than listening on a door nobody can open. An interactive login lands in tmux, so the durable session is what a connection reaches.

Host keys live on a mounted volume rather than in the image. An image-baked host key would be identical on every pair running that image — the shared-credential case C6 forbids — and a key regenerated per start would trip every client's host-key check on each relaunch, training the operator to accept a changed key.

Ports and the tailnet hostname are adapter values, so a third lineage sets its own without touching a unit.

The maintainer stated that both components being tailnet nodes "should be part of the objective". That is a charter amendment and therefore his to confirm and merge; this record captures the decision and the implementation, and the objective's text stands unchanged until he changes it.
