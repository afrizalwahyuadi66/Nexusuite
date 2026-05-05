import requests
import time
import sys
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout

console = Console()

class NexusuiteDashboard:
    def __init__(self, base_url: str = "http://localhost:8000/api/v1"):
        self.base_url = base_url

    def get_all_jobs(self):
        api_key = os.getenv("NX_ADMIN_KEY", "admin-secret-key")
        try:
            resp = requests.get(f"{self.base_url}/scans", headers={"X-API-Key": api_key}, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            return []
        except:
            return []

    def generate_table(self) -> Table:
        table = Table(title="Nexusuite v4.0 Active Scans", expand=True)
        table.add_column("Job ID", style="cyan", no_wrap=True)
        table.add_column("Target", style="magenta")
        table.add_column("Status", style="green")
        table.add_column("Findings", justify="right", style="red")
        table.add_column("Progress", style="blue")

        jobs = self.get_all_jobs()
        if not jobs:
            table.add_row("-", "No active scans", "-", "0", "0%")
            return table

        for job_id, job in jobs.items():
            findings_count = len(job.get('findings', []))
            status = job.get('status', 'unknown')
            
            # Simple color mapping
            status_style = "green"
            if status == "running": status_style = "yellow"
            elif status == "failed": status_style = "bold red"
            
            table.add_row(
                job_id[:8], 
                job.get('target', 'unknown'), 
                f"[{status_style}]{status}[/]", 
                str(findings_count),
                "100%" if status == "completed" else "Running..."
            )
        
        return table

    def run(self):
        with Live(self.generate_table(), refresh_per_second=1) as live:
            try:
                while True:
                    time.sleep(1)
                    live.update(self.generate_table())
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Exiting Dashboard...[/]")

if __name__ == "__main__":
    dash = NexusuiteDashboard()
    dash.run()
