import json
import sys

with open('C:\\Users\\mlest\\.gemini\\antigravity-ide\\brain\\ed394a9e-205f-4669-90ac-0c472f52d84f\\.system_generated\\logs\\transcript_full.jsonl') as f:
    lines = f.readlines()

for line in reversed(lines):
    try:
        data = json.loads(line)
        if data.get('type') == 'PLANNER_RESPONSE':
            for tc in data.get('tool_calls', []):
                if tc['name'] == 'write_to_file' and 'mask.go' in tc['args'].get('TargetFile', ''):
                    print(tc['args']['CodeContent'])
                    sys.exit(0)
                elif tc['name'] == 'replace_file_content' and 'mask.go' in tc['args'].get('TargetFile', ''):
                    print(tc['args']['ReplacementContent'])
                    sys.exit(0)
    except:
        pass
