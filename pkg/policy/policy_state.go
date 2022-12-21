package policy

type PolicyState struct {
	configuredState *OrderedDict
	pendingState    *OrderedDict
}

func NewPolicyState() *PolicyState {
	return &PolicyState{
		configuredState: NewOrderedDict(),
		pendingState:    NewOrderedDict(),
	}
}

type OrderedDict struct {
	lookup map[string]*Node
	list   *LinkedList
}

type Node struct {
	prev  *Node
	next  *Node
	value interface{}
}

type LinkedList struct {
	head *Node
	tail *Node
}

func NewLinkedList() *LinkedList {
	list := &LinkedList{
		head: &Node{value: nil},
		tail: &Node{value: nil},
	}
	list.head.next = list.tail
	list.tail.prev = list.head
	return list
}

func (ll *LinkedList) Append(value interface{}) *Node {
	n := &Node{
		prev:  ll.tail.prev,
		next:  ll.tail,
		value: value,
	}

	ll.tail.prev.next = n
	ll.tail.prev = n

	return n
}

func (ll *LinkedList) Remove(n *Node) bool {
	if n == ll.head || ll.tail == n {
		return false
	}
	n.prev.next = n.next
	n.next.prev = n.prev
	return true
}

func (ll *LinkedList) Iterate() chan *Node {
	ch := make(chan *Node)
	go func() {
		n := ll.head
		for n.next != ll.tail {
			ch <- n.next
			n = n.next
		}
		close(ch)
	}()

	return ch
}

func NewOrderedDict() *OrderedDict {
	return &OrderedDict{
		lookup: make(map[string]*Node),
		list:   NewLinkedList(),
	}
}

func (d *OrderedDict) Set(key string, value interface{}) {
	if n, exist := d.lookup[key]; exist {
		// if exist replace the value
		n.value = value
	} else {
		d.lookup[key] = d.list.Append(value)
	}
}

func (d *OrderedDict) Get(key string) interface{} {
	v, exist := d.lookup[key]
	if !exist {
		return nil
	}
	return v.value
}

func (d *OrderedDict) Remove(key string) bool {
	if n, exist := d.lookup[key]; exist {
		if ok := d.list.Remove(n); !ok {
			return false
		}
		delete(d.lookup, key)
		return true
	}
	return false
}

func (d *OrderedDict) Iterate() chan interface{} {
	ch := make(chan interface{})
	go func() {
		for v := range d.list.Iterate() {
			ch <- v.value
		}
		close(ch)
	}()
	return ch
}
