#!/usr/bin/env python3
import sys
import os
import json
import torch
from huggingface_hub import hf_hub_download
from transformers import PreTrainedTokenizerFast

MODEL_REPO = "HadrianSecurity/subwiz"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gpt_model import GPT

class LLMInference:
    def __init__(self):
        model_path = hf_hub_download(repo_id=MODEL_REPO, filename='model.pt')
        tokenizer_path = hf_hub_download(repo_id=MODEL_REPO, filename='tokenizer.json')
        
        self.model = GPT.from_checkpoint(model_path, device='cpu', tokenizer_path=tokenizer_path)
        self.model.eval()
        self.tokenizer = PreTrainedTokenizerFast(
            tokenizer_file=tokenizer_path, 
            clean_up_tokenization_spaces=True
        )
    
    def predict(self, subdomains, apex, num_predictions=500, max_tokens=10, temperature=0.0, blocked=None):
        blocked = blocked or []
        
        tokenizer_input = ",".join(sorted(subdomains)) + "[DELIM]"
        x = self.tokenizer.encode(tokenizer_input)
        x = [1] * (self.model.config.block_size - len(x)) + x
        x = torch.tensor(x)
        
        blocked_outputs = set(blocked)
        
        predictions = self.model.generate(
            x,
            max_new_tokens=max_tokens,
            topn=num_predictions,
            temperature=temperature,
            blocked_outputs=blocked_outputs,
        )
        predictions = predictions.int().tolist()
        
        results = []
        for pred in predictions:
            decoded = self.tokenizer.decode(pred).replace(" ", "").rsplit("[DELIM]", 1)
            if len(decoded) > 1:
                subdomain = decoded[1]
                full_domain = subdomain + "." + apex
                results.append(full_domain)
        
        return results

if __name__ == "__main__":
    try:
        input_json = sys.stdin.read()
        input_data = json.loads(input_json)
        
        llm = LLMInference()
        predictions = llm.predict(
            subdomains=input_data.get("subdomains", []),
            apex=input_data.get("apex", ""),
            num_predictions=input_data.get("num_predictions", 500),
            max_tokens=input_data.get("max_tokens", 10),
            temperature=input_data.get("temperature", 0.0),
            blocked=input_data.get("blocked", [])
        )
        
        print(json.dumps({"predictions": predictions}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

