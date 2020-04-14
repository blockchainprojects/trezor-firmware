"""
General representation of a parsing Node.
"""


class AbstractNode:
    def parse(self) -> "AbstractNode":
        ...

    def write(self, w: Writer) -> None:
        ...


"""
LeafNode representing a leaf in the parsing tree.

LeafNodes implement a generalized parse function which applies certain
transform operations on the given data. Furthermore each LeafNode has its
own write function since they are the most low level items in the parsing
tree structure.
"""


class LeafNode(AbstractNode):
    def parse(self) -> "LeafNode":
        if self.data is None:
            raise ValueError
        return self

    def write(self, w: Writer) -> None:
        ...

    def __str__(self) -> str:
        return str(self.data)


"""
Node represents a subtree in the parsing tree. A Node can consist of more Nodes
or LeafNodes.

The parse and write function apply their operations on their children.
"""


class Node(AbstractNode):
    def parse(self) -> "Node":
        if self.data is None:
            raise ValueError

        for node_name, NodeCls in self.nodes.items():
            try:
                node_msg = getattr(self.data, node_name)
                node = NodeCls(node_msg).parse()
                self.nodes[node_name] = node
            except ValueError as prev_ex:
                next_ex = "{}:{}".format(node_name, prev_ex)
                raise ValueError(next_ex)

        return self

    def write(self, w: Writer) -> None:
        for node in self.nodes.values():
            node.write(w)

    def __getitem__(self, val):
        return self.nodes[val]


"""
A WrapperNode is an extension of a Node and can be Wrapped around any
AbstractNode.

Currently Optional, Array, SortedArray are WrapperNodes.
"""


class WrapperNode(Node):
    def __call__(self, msg):
        ...
