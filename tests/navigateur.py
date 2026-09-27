# SPDX-License-Identifier: EUPL-1.2
"""Scénario navigateur de tests/navigateur.sh (Playwright, Chromium sans interface)."""

import os
import re
import sys
import time

from playwright.sync_api import expect, sync_playwright

U = "http://localhost:8095"
LOG = "/work/data/mail.log"


def ok(message):
    print("OK  " + message, flush=True)


def ko(message):
    print("ÉCHEC " + message, flush=True)
    sys.exit(1)


def mails():
    return open(LOG, encoding="utf-8").read() if os.path.exists(LOG) else ""


def check(condition, message):
    ok(message) if condition else ko(message)


with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context(locale="fr-FR")
    # Mesure d'audience neutralisée : aucune visite de test n'est envoyée à stats.otspi.org.
    context.route(re.compile(r"^https?://stats\.otspi\.org/"), lambda route: route.fulfill(status=200, content_type="application/javascript", body=""))
    page = context.new_page()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    expect.set_options(timeout=15000)

    # Formulaire : la preuve de travail est calculée par le navigateur pendant la saisie.
    page.goto(U + "/")
    page.fill("input[name=prenom]", "Ada")
    page.fill("input[name=nom]", "Lovelace")
    page.fill("input[name=email]", "ada@example.org")
    page.fill("input[name=organisation]", "Inria")
    page.check("input[name=publier]")
    page.wait_for_function("document.querySelector('input[name=pow]').value !== ''", timeout=60000)
    ok("formulaire : preuve de travail calculée par le navigateur")
    time.sleep(4.5)  # délai minimal de remplissage
    page.click("form[data-pow] button[type=submit]")
    expect(page.locator("h1")).to_contain_text("Vérifiez votre boîte")
    check("TO: ada@example.org" in mails(), "formulaire envoyé et accepté par le serveur")

    # Confirmation puis partage : copie du lien du manifeste.
    link = re.findall(r"confirm\.php\?t=[0-9a-f]+&lang=fr", mails())[-1]
    page.goto(U + "/" + link)
    page.click("form button[type=submit]")
    expect(page.locator("h1")).to_contain_text("Signature confirmée")
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=U)
    copy = page.locator(".share-copy")
    expect(copy).to_be_visible()
    copy.click()
    expect(copy).to_have_text("Lien copié")
    check("manifeste.html" in page.evaluate("navigator.clipboard.readText()"), "partage : lien du manifeste copié")

    # Administration : clé de sécurité virtuelle (CTAP2, vérification de l'utilisateur).
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "usb", "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
    invitation = re.findall(r"admin\.php\?inv=[A-Za-z0-9_-]+", mails())[-1]
    page.goto(U + "/" + invitation)
    page.click("form[data-webauthn=create] button")
    expect(page.get_by_text("session en cours")).to_be_visible()
    ok("clé de sécurité enregistrée depuis le navigateur")
    page.click("text=Se déconnecter")
    page.click("form[data-webauthn=get] button")
    expect(page.get_by_role("button", name="Se déconnecter")).to_be_visible()
    ok("connexion avec la clé de sécurité")

    # Sans vérification de l'utilisateur (code PIN), la connexion n'aboutit pas.
    page.click("text=Se déconnecter")
    cdp.send("WebAuthn.setUserVerified", {"authenticatorId": authenticator, "isUserVerified": False})
    page.click("form[data-webauthn=get] button")
    expect(page.locator(".webauthn-status, [role=alert]").first).to_contain_text(re.compile("refus|annulée"))
    check(page.get_by_role("button", name="Se déconnecter").count() == 0, "connexion refusée sans code PIN")
    cdp.send("WebAuthn.setUserVerified", {"authenticatorId": authenticator, "isUserVerified": True})
    page.goto(U + "/admin.php")
    page.click("form[data-webauthn=get] button")
    expect(page.get_by_role("button", name="Se déconnecter")).to_be_visible()

    # Modération par lot : « Tout sélectionner » puis validation.
    page.goto(U + "/admin.php?f=attente")
    page.check("[data-select-all]")
    boxes = page.locator("input[name='ids[]']")
    check(boxes.count() >= 1 and all(boxes.nth(i).is_checked() for i in range(boxes.count())), "tout sélectionner coche les signatures à modérer")
    page.click("text=Valider la sélection")
    expect(page.locator(".notice")).to_contain_text("validée(s)")
    ok("validation par lot depuis le navigateur")

    # Aucune erreur JavaScript ni violation de la politique de sécurité (CSP) sur les pages parcourues.
    check(not errors, "aucune erreur JavaScript ni CSP" + ("" if not errors else " : " + " | ".join(errors[:3])))
    browser.close()

print("Tous les tests navigateur passent.")
