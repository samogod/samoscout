package llm

type Config struct {
	NumPredictions    int
	MaxRecursion      int
	MaxTokens         int
	Temperature       float32
	ResolutionThreads int
	Device            string
	OutputDir         string
	Verbose           bool
}

type ModelConfig struct {
	BlockSize int     `json:"block_size"`
	VocabSize int     `json:"vocab_size"`
	NLayer    int     `json:"n_layer"`
	NHead     int     `json:"n_head"`
	NEmbd     int     `json:"n_embd"`
	Dropout   float32 `json:"dropout"`
	Bias      bool    `json:"bias"`
}

