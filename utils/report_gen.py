import json

class ReportGenerator:
    def __init__(self, data):
        self.data = data

    def generate_txt(self, filename):
        with open(filename, 'w') as f:
            f.write("LPE-AUDIT-PRO SECURITY REPORT\n")
            f.write("="*30 + "\n\n")
            for section, content in self.data.items():
                f.write(f"[+] SECTION: {section.upper()}\n")
                f.write("-" * 20 + "\n")
                f.write(json.dumps(content, indent=4))
                f.write("\n\n")

    def generate_json(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)