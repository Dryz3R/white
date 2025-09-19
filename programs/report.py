import json
from datetime import datetime

def generate_report(data, filename):
    report = {
        "timestamp": datetime.now().isoformat(),
        "data": data
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report saved to {filename}")