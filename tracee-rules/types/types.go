package types

type Signature interface {
	GetMetadata() SignatureMetadata
	GetSignatureEventSelectors() []SignatureEventSelector
	Init(cb SignatureHandler) error
	OnEvent(event Event) error
	OnSignal(signal Signal) error
}
type SignatureMetadata struct {
	Name        string
	Description string
	Tags        []string
	Properties  map[string]interface{}
}

type SignatureEventSelector struct {
	Source string
	Name   string
}
type SignatureHandler func(found Finding)

type Event interface{}

type Signal interface{}
type SignalSourceComplete string

type Finding struct {
	Data      []FindingData
	Context   Event
	Signature Signature
}
type FindingData struct {
	Type       string
	Properties map[string]interface{}
}

type TraceeEvent struct {
	Timestamp           float64               `json:"timestamp"`
	ProcessID           int                   `json:"processId"`
	ThreadID            int                   `json:"threadId"`
	ParentProcessID     int                   `json:"parentProcessId"`
	HostProcessID       int                   `json:"hostProcessId"`
	HostThreadID        int                   `json:"hostThreadId"`
	HostParentProcessID int                   `json:"hostParentProcessId"`
	UserID              int                   `json:"userId"`
	MountNS             int                   `json:"mountNamespace"`
	PIDNS               int                   `json:"pidNamespace"`
	ProcessName         string                `json:"processName"`
	HostName            string                `json:"hostName"`
	EventID             int                   `json:"eventId,string"`
	EventName           string                `json:"eventName"`
	ArgsNum             int                   `json:"argsNum"`
	ReturnValue         int                   `json:"returnValue"`
	Args                []TraceeEventArgument `json:"args"`
}
type TraceeEventArgument struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}
