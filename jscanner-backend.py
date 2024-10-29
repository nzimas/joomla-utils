import time
import random
import argparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, NoSuchElementException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from collections import defaultdict
import requests

# Function to simulate human-like typing
def human_typing(element, text, delay=0.1):
    for char in text:
        element.send_keys(char)
        time.sleep(delay * (0.5 + random.uniform(0, 1)))

# Function to simulate random pauses
def human_pause(min_time=1, max_time=3):
    time.sleep(random.uniform(min_time, max_time))

# Function to scroll like a human
def human_scroll(driver):
    scroll_pause = random.uniform(1, 3)
    driver.execute_script("window.scrollBy(0, window.innerHeight/2);")
    time.sleep(scroll_pause)
    driver.execute_script("window.scrollBy(0, window.innerHeight/2);")
    time.sleep(scroll_pause)

# Setting up argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description='Login to Joomla 5 and scan admin UI for errors.')
    parser.add_argument('url', type=str, help='Admin login URL of the Joomla website')
    parser.add_argument('username', type=str, help='Username for Joomla admin login')
    parser.add_argument('password', type=str, help='Password for Joomla admin login')
    parser.add_argument('report_file', type=str, help='File to report errors')
    return parser.parse_args()

# Function to get HTTP status code
def get_status_code(url):
    try:
        response = requests.get(url)
        return response.status_code
    except requests.RequestException as e:
        print(f"Failed to get status code for {url}: {e}")
        return None

# Scanning for errors
def scan_for_errors(driver, report_file):
    visited_links = set()  # Keep track of visited links to avoid re-scanning the same pages
    links = driver.find_elements(By.TAG_NAME, "a")
    links_to_scan = [link.get_attribute('href') for link in links if link.get_attribute('href') and '/administrator/' in link.get_attribute('href') and 'logout' not in link.get_attribute('href').lower() and 'save' not in link.get_attribute('href').lower() and 'upload' not in link.get_attribute('href').lower() and 'download' not in link.get_attribute('href').lower() and 'backup' not in link.get_attribute('href').lower()]
    
    error_dict = defaultdict(list)  # Dictionary to store errors by type
    pages_scanned = 0  # Counter for pages scanned

    for href in links_to_scan:
        try:
            if href not in visited_links:
                visited_links.add(href)
                pages_scanned += 1
                human_pause(2, 5)

                # Get the HTTP status code for the page
                status_code = get_status_code(href)
                if status_code:
                    if status_code == 404:
                        error_dict['404'].append(href)
                        print(f"404 Error found on page: {href}")
                    elif status_code == 500:
                        error_dict['500'].append(href)
                        print(f"500 Error found on page: {href}")
                    elif status_code == 403:
                        error_dict['403'].append(href)
                        print(f"403 Error found on page: {href}")
                    elif status_code == 401:
                        error_dict['401'].append(href)
                        print(f"401 Error found on page: {href}")
                
                # Visit the page using Selenium for deeper inspection
                driver.get(href)
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                human_scroll(driver)
                # Check if driver is still valid
                if len(driver.window_handles) == 0:
                    print(f"Skipping {href} as the browser window is closed.")
                    break
                # Look for specific Joomla error indicators in the HTML source
                error_elements = driver.find_elements(By.CLASS_NAME, "alert-error") + driver.find_elements(By.CLASS_NAME, "error-message")
                if error_elements:
                    error_details = "\n".join([el.text for el in error_elements])
                    error_dict['General Error'].append(f"{href}\nDetails: {error_details}")
                    print(f"General Error found on page: {href}\nDetails: {error_details}")
        except (StaleElementReferenceException, TimeoutException, NoSuchElementException, WebDriverException) as e:
            print(f"Exception occurred while scanning link: {str(e)}. Retrying...")
            continue
        except Exception as e:
            print(f"Unexpected error occurred while scanning {href}: {str(e)}")

    # Write errors to report file
    with open(report_file, 'w') as file:
        file.write(f"Total pages scanned: {pages_scanned}\n\n")
        for error_type, pages in error_dict.items():
            file.write(f"{error_type} Errors:\n")
            for page in pages:
                file.write(f"  {page}\n")
            file.write("\n")

# Main function
def main():
    args = parse_arguments()

    # Set up Chrome options to simulate normal browser usage
    chrome_options = Options()
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--incognito")
    chrome_options.add_argument("--start-maximized")
    
    # Launch Chrome using ChromeDriverManager to manage installation
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    driver.get(args.url)

    # Simulate human typing for the login fields
    username_field = driver.find_element(By.ID, "mod-login-username")
    human_typing(username_field, args.username, delay=0.2)
    human_pause(1, 3)

    password_field = driver.find_element(By.ID, "mod-login-password")
    human_typing(password_field, args.password, delay=0.2)
    human_pause(1, 3)

    # Simulate human pressing the login button
    login_button = driver.find_element(By.ID, "btn-login-submit")
    login_button.click()
    human_pause(3, 5)

    # Scan the admin UI for errors after login
    try:
        scan_for_errors(driver, args.report_file)
    except WebDriverException as e:
        print(f"Unexpected browser error: {str(e)}")

    # Close the browser session
    driver.quit()

if __name__ == "__main__":
    main()
