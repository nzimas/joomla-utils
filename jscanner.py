import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time

# User-defined settings
default_username = "username"
default_password = "password"
default_output = "report.txt"
default_report_404 = "yes"
default_scan_limit = 0
default_nav_links_only = "yes"

class JoomlaSiteScanner:
    def __init__(self, base_url, username, password, report_404=True, scan_limit=0, nav_links_only=False):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.report_404 = report_404
        self.scan_limit = scan_limit
        self.nav_links_only = nav_links_only
        self.session = requests.Session()
        self.visited_urls = set()
        self.errors = []
        self.stats = {
            "total_pages": 0,
            "total_errors": 0
        }

    def login(self):
        # Get the homepage to retrieve CSRF tokens or hidden fields
        response = self.session.get(self.base_url)

        if response.status_code != 200:
            raise Exception("Failed to load homepage for login.")

        soup = BeautifulSoup(response.content, 'html.parser')

        # Try to find the login form by common characteristics
        login_form = None
        forms = soup.find_all('form')

        for form in forms:
            # Check if the form has fields that look like a login form
            form_inputs = form.find_all("input")
            has_username = any(input.get("name") in ["username", "user", "jform[username]"] for input in form_inputs)
            has_password = any(input.get("name") in ["password", "pass", "jform[password]"] for input in form_inputs)

            if has_username and has_password:
                login_form = form
                break

        if not login_form:
            raise Exception("Login form not found on homepage. Please check the homepage structure.")

        # Prepare the payload for login
        payload = {
            "username": self.username,
            "password": self.password,
        }

        # Extract hidden fields (including CSRF tokens)
        for hidden_input in login_form.find_all("input", type="hidden"):
            if hidden_input.get("name") and hidden_input.get("value"):
                payload[hidden_input["name"]] = hidden_input["value"]

        # Find the action URL for the login form
        login_action = login_form.get("action")
        if not login_action:
            raise Exception("Login form action URL not found.")

        login_url = urljoin(self.base_url, login_action)

        # Submit the login form with the payload
        try:
            response = self.session.post(login_url, data=payload)
            if response.status_code == 200 and ('Logout' in response.text or 'logout' in response.text):
                print("Successfully logged in.")
            else:
                raise Exception("Login failed. Please check your credentials or the login form parameters.")
        except requests.RequestException as e:
            raise Exception(f"Login request failed: {str(e)}")

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def scan_url(self, url):
        if url in self.visited_urls or not self.is_valid_url(url):
            return

        if self.scan_limit > 0 and self.stats["total_pages"] >= self.scan_limit:
            print("Scan limit reached. Stopping further scans.")
            return

        try:
            print(f"Scanning URL: {url}")
            response = self.session.get(url, timeout=10)
            self.visited_urls.add(url)
            self.stats["total_pages"] += 1

            if response.status_code != 200:
                if response.status_code == 404 and not self.report_404:
                    return
                self.errors.append((url, response.status_code))
                self.stats["total_errors"] += 1

            soup = BeautifulSoup(response.content, "html.parser")
            self.scan_links(soup, url)
        except requests.RequestException as e:
            self.errors.append((url, str(e)))
            self.stats["total_errors"] += 1

    def scan_links(self, soup, base_url):
        if self.nav_links_only:
            # Only scan navigational links (menu links)
            nav_links = soup.find_all(['nav', 'menu', 'ul'])
            for nav in nav_links:
                for link in nav.find_all("a", href=True):
                    href = urljoin(base_url, link.get("href"))
                    if self.is_valid_url(href) and urlparse(href).netloc == urlparse(self.base_url).netloc:
                        self.scan_url(href)
        else:
            # Scan all links
            for link in soup.find_all("a", href=True):
                href = urljoin(base_url, link.get("href"))
                if self.is_valid_url(href) and urlparse(href).netloc == urlparse(self.base_url).netloc:
                    self.scan_url(href)

    def generate_report(self):
        report = f"--- Joomla Site Scan Report ---\n"
        report += f"Base URL: {self.base_url}\n"
        report += f"Total Pages Scanned: {self.stats['total_pages']}\n"
        report += f"Total Errors Found: {self.stats['total_errors']}\n\n"

        error_types = {}
        for error in self.errors:
            error_code = error[1]
            if error_code not in error_types:
                error_types[error_code] = []
            error_types[error_code].append(error[0])

        report += f"--- Errors by Type ---\n"
        for error_code, urls in error_types.items():
            report += f"Error {error_code}:\n"
            for url in urls:
                report += f"  - {url}\n"

        return report

    def save_report(self, filename="report.txt"):
        with open(filename, "w") as file:
            file.write(self.generate_report())

def main():
    parser = argparse.ArgumentParser(description="Simple Joomla Site Scanner with Authentication")
    parser.add_argument("base_url", help="Base URL of the Joomla site to scan (e.g., http://localhost/joomla/)")
    parser.add_argument("--username", help="Username for Joomla login", default=default_username)
    parser.add_argument("--password", help="Password for Joomla login", default=default_password)
    parser.add_argument("--output", help="Output file for the report", default=default_output)
    parser.add_argument("--report-404", help="Whether to report 404 errors (yes/no)", default=default_report_404)
    parser.add_argument("--scan-limit", help="Limit the number of URLs to scan (0 for no limit)", type=int, default=default_scan_limit)
    parser.add_argument("--nav-links-only", help="Whether to scan only navigational links (yes/no)", default=default_nav_links_only)
    args = parser.parse_args()

    report_404 = args.report_404.lower() == "yes"
    nav_links_only = args.nav_links_only.lower() == "yes"

    scanner = JoomlaSiteScanner(args.base_url, args.username, args.password, report_404=report_404, scan_limit=args.scan_limit, nav_links_only=nav_links_only)
    scanner.login()  # Authenticate before scanning
    print("Starting scan...")
    scanner.scan_url(args.base_url)
    scanner.save_report(args.output)

    print(f"Scan completed. Report saved to {args.output}")

if __name__ == "__main__":
    main()
