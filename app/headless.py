# -*- coding: utf-8 -*-
"""
    app.headless
    ~~~~~~~~~~~~

    Provides Chrome headless browser login functionality
"""
from pathlib import Path
from subprocess import check_output, CalledProcessError
from time import sleep
from sys import platform

import pygogo as gogo

from config import Config

try:
    from selenium import webdriver
except ModuleNotFoundError:
    webdriver = None
    NoSuchElementException = WebDriverException = None
    Options = None
else:
    from selenium.common.exceptions import NoSuchElementException, WebDriverException
    from selenium.webdriver.chrome.options import Options

CHROME_DRIVER_VERSIONS = Config.CHROME_DRIVER_VERSIONS

logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False


def get_def_chromedriver_path(version=None):
    executable = f"chromedriver-{version}" if version else "chromedriver"
    command = f"which {executable}"

    try:
        _chromedriver_path = check_output(command, shell=True, encoding="utf-8")
    except CalledProcessError:
        chromedriver_path = ""
    else:
        chromedriver_path = _chromedriver_path.strip()

    return chromedriver_path


def get_os():
    if platform.startswith("freebsd"):
        operating_system = "freebsd"
    elif platform.startswith("linux"):
        operating_system = "linux"
    elif platform.startswith("aix"):
        operating_system = "aix"
    elif platform.startswith("win32"):
        operating_system = "windows"
    elif platform.startswith("cygwin"):
        operating_system = "cygwin"
    elif platform.startswith("darwin"):
        operating_system = "mac"
    else:
        operating_system = "other"

    return operating_system


# get system specific chromedriver (currently version 78)
def get_chromedriver_path(operating_system):
    chromedriver_path = None
    unixlike = operating_system in {"mac", "linux"}

    if unixlike:
        # TODO: make this check cross platform
        for version in CHROME_DRIVER_VERSIONS:
            _chromedriver_path = get_def_chromedriver_path(version)

            if _chromedriver_path:
                chromedriver_path = Path(_chromedriver_path)
                break

    if not chromedriver_path:
        driver_name = "chromedriver"

        if operating_system == "windows":
            driver_name += ".exe"

        chromedriver_path = Path.cwd() / operating_system / driver_name

    return chromedriver_path


def find_element_loop(browser, selector, count=0, max_retries=10):
    try:
        elem = browser.find_element_by_css_selector(selector)
    except NoSuchElementException:
        if count < max_retries:
            sleep(0.5)
            kwargs = {"count": count + 1, "max_retries": max_retries}
            elem = find_element_loop(browser, selector, **kwargs)
        else:
            elem = None

    return elem


def save_page(browser, page_name, with_html=True):
    logger.debug(f"taking screenshot of {page_name}...")
    browser.save_screenshot(f"{page_name}.png")

    with open(f"{page_name}.html", "w") as f:
        print(f"saving html of {page_name}...")
        f.write(browser.page_source)


def _headless_auth(redirect_url, prefix, username=None, password=None, **kwargs):
    options = Options()
    options.headless = True
    chrome_path = kwargs["chrome_path"]
    username_selector = kwargs["username_selector"]
    password_selector = kwargs["password_selector"]
    sign_in_selector = kwargs["sign_in_selector"]
    elements = kwargs.get("elements") or []
    debug = kwargs.get("debug")

    browser = webdriver.Chrome(executable_path=chrome_path, chrome_options=options)

    # navigate to auth page
    browser.get(redirect_url)
    browser.implicitly_wait(3)

    #######################################################
    # TODO: Check to see if this is required when logging
    # in without a headless browser (might remember creds).
    username_element = browser.find_element_by_css_selector(username_selector)

    if username_element and username:
        username_element.clear()
        username_element.send_keys(username)
    else:
        if not username:
            logger.error("No username supplied!")

        if not username_element:
            logger.error(f"Selector '{username_selector}' not found!")

    password_element = browser.find_element_by_css_selector(password_selector)

    if password_element and password:
        password_element.clear()
        password_element.send_keys(password)
    else:
        if not password:
            logger.error("No password supplied!")

        if not password_selector:
            logger.error(f"Selector '{password_selector}' not found!")

    if debug:
        save_page(browser, "1 - login")

    sign_in = browser.find_element_by_css_selector(sign_in_selector)

    # TODO: why does it stall here for timero??
    error_msg = f"Selector '{sign_in_selector}' not found!"
    sign_in.click() if sign_in else logger.error(error_msg)

    if debug:
        save_page(browser, "2 - logged in")
    #######################################################

    for pos, element in enumerate(elements):
        selector = element["selector"]
        el = find_element_loop(browser, selector)
        error_msg = "'{description}' selector '{selector}' not found!"
        el.click() if el else logger.error(error_msg.format(**element))

        if debug:
            save_page(browser, "{0} - {description}".format(pos + 3, **element))

    # TODO: Error if there are any button elements on the page
    browser.close()


def headless_auth(redirect_url, prefix, **kwargs):
    failed = True
    operating_system = get_os()
    chrome_path = get_chromedriver_path(operating_system)

    try:
        _headless_auth(redirect_url, prefix, chrome_path=chrome_path, **kwargs)
    except TypeError:
        logger.error("selenium not installed!")
    except WebDriverException as e:
        if "executable needs to be in PATH" in str(e):
            logger.error(f"chromedriver executable not found in {chrome_path}!")
        else:
            logger.error(e)
    except AttributeError as e:
        logger.error(e)
    else:
        failed = False
        logger.debug("Headless auth succeeded!")
    finally:
        if failed:
            logger.error("Headless auth failed!")

        return failed
