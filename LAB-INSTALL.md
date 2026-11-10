# Laboranleitung für die Benutzerverwaltung — Entwurf

**Nur für ein isoliertes Testsystem.** Dieser Entwurf wurde noch nicht mit einem echten Traefik-/Authelia-Stack vollständig durchgetestet und ist keine Freigabe für ein öffentliches System. Bitte zuerst README und die Release-Lücken lesen.

## Was die Komponenten tun

Authelia übernimmt Anmeldung und 2FA. Ein separater Python-Dienst bietet Einladungen, Kontosperre und erlaubte Gruppen. Traefik nimmt HTTPS entgegen, entfernt vom Client gelieferte Identitätsheader und ruft für die Administrationsrouten Authelia ForwardAuth auf. Der Python-Dienst akzeptiert Identität ausschließlich vom exakt konfigurierten Proxy und prüft den Administrator zusätzlich. Alle drei Grenzen sind erforderlich.

Dieser Code stammt aus einer Installation mit Authelia **4.39.16** und einem separat gebauten Patch für die gemeinsame Sperre der Benutzerdatei. Upstream ohne diesen passenden Patch ist bei gleichzeitigen Änderungen über die Authelia-Passwortfunktion und die Verwaltung nicht nachweislich sicher. Der Patch ist versionsgebunden; nicht blind auf andere Versionen anwenden. Ein reproduzierbarer allgemeiner Image-Build und ein vollständiger End-to-End-Test fehlen noch. Die native Settings-UI im Ordner `native_ui/` ist experimentell, passt wegen geändertem Hash nicht zum Builder und ist nicht Teil der Installationsanleitung. Die Verwaltung wird später direkt unter `/onboarding/admin` aufgerufen.

## Vorbedingungen

- Isolierter Debian-13-Testhost; bestehende, funktionierende Authelia-/Traefik-Installation mit HTTPS und einem bereits eingerichteten 2FA-Administratorkonto.
- Funktionierendes Backup und Rückfallplan für Authentifizierung, Benutzerdatei, Datenbank und Verschlüsselungsschlüssel; keine produktiven Daten für das Labor verwenden.
- Python 3 mit PyYAML; systemd; Docker mit einem kompatiblen, lokal erreichbaren Container namens `authelia`, dessen CLI `authelia crypto hash generate argon2 --no-confirm` unterstützt. Der Dienst benötigt derzeit Root-Rechte und Docker-Zugriff: entsprechend hohen Vertrauensbereich beachten.
- Geeignete Datei- und Verzeichniseigentümer: die Benutzerdatei muss den strengen Eigentümer-/Modusprüfungen des Dienstes entsprechen und der Dienst benötigt Schreibzugriff auf das Konfigurationsverzeichnis. Das systemd-Beispiel erwartet `/opt/authelia/config`.
- Prüfen, ob aktuelle Traefik-/Authelia-Versionen und deren Autorisierungsendpunkte die Beispielkonfiguration unterstützen. Benutzerdatei, Onboarding und native Passwortänderungen müssen dieselbe `.lock`-Datei verwenden.

## Parameter im Labor festlegen

Datei `/etc/authelia-onboarding/config.env` nur für Root lesbar erstellen, z. B. mit diesen **nicht geheimen Beispielwerten**, angepasst an die tatsächlich geprüfte Topologie:

```ini
ONBOARDING_ADMINS=admin
ONBOARDING_TRUSTED_PROXY=10.77.0.10
ONBOARDING_ORIGIN=https://auth.example.invalid
ONBOARDING_BIND_IP=10.77.0.11
ONBOARDING_BIND_PORT=9945
ONBOARDING_ALLOWED_GROUPS=students
AUTHELIA_USERS_DB=/opt/authelia/config/users_database.yml
ONBOARDING_DB=/var/lib/authelia-onboarding/state.sqlite3
```

Die Administratoren müssen exakt den Authelia-Benutzernamen entsprechen; der Dienst verlangt Kleinbuchstaben. Die Proxy-IP muss die am Dienst tatsächlich ankommende Quell-IP sein. Niemals `0.0.0.0` als Bind-Adresse verwenden. Der Origin muss die tatsächlich benutzte HTTPS-Origin sein; ohne abschließenden Slash oder Pfad. Die Gruppenliste ist eine explizite Rechtefreigabe: nur geprüfte, durch diesen Dienst verwaltbare Gruppen eintragen oder leer lassen. Bestehende nicht freigegebene Gruppen bleiben bei Änderungen erhalten.

## Geplanter Laborablauf

1. Eine **passende** und gemeinsam sperrende Authelia-Variante in einem Einweg-Labor bauen und prüfen. Versionsgebundenen Patch und seine Provenienz unter `scripts/authelia_onboarding/patches/` beachten; vorhandene produktive Datenbank nicht verwenden.
2. Die Dateien aus `scripts/authelia_onboarding/` vollständig als root-eigene Dateien in ein isoliertes `/opt/authelia-onboarding/` übertragen. State- und Konfigurationsverzeichnisse entsprechend der Unit vorbereiten und die Env-Datei schützen. Nicht blind die Beispiel-IP übernehmen.
3. `traefik-onboarding.yaml` als **Vorlage** an die lokalen Hostnamen, Adressen und tatsächlichen Entrypoint-/Middleware-Namen anpassen; weder Dienst-Port noch Docker-Socket im Internet erreichbar machen. Der Dienst ist auf Netzwerkebene nur vom angegebenen Traefik-Peer erreichbar.
4. Vor einer etwaigen Konfigurationsänderung prüfen: die Admin-Routen müssen mit expliziten Benutzer-Subjects `two_factor` und unmittelbar danach `deny` vor dem Portal-Bypass liegen. Authelia wertet Regeln der Reihe nach aus. Das bereitliegende `config_patch.py` lehnt nicht eindeutig disjunkte frühere Regeln ab; auf einer Kopie testen, Änderungen begutachten und passende Authelia-Konfigurationsvalidierung verwenden. Ein Tool-Lauf allein ist kein Sicherheitsnachweis.
5. Beispiel-Unit erst im Labor installieren, `systemctl daemon-reload` und Dienststart ausführen und im Journal ausschließlich nicht-sensitive Fehlermeldungen prüfen. Keinen geheimen Inhalt, QR-Code oder Einladungslink in ein öffentliches Log schreiben.
6. Vor Freigabe die folgenden Tests mit eigens angelegten Testkonten ausführen; bei jedem Fehler stoppen und den Dienst nicht öffentlich freischalten.

## Mindestprüfungen vor jedem Einsatz

- Eine unangemeldete Anfrage an Admin und API wird abgewiesen oder zur Anmeldung geführt; ein angemeldeter Nicht-Admin erhält keinen Zugriff.
- Der Administrator kommt erst nach gültigem zweiten Faktor zur Verwaltung. Teste auch frische Sitzungen und Ablauf.
- Direkter Backendzugriff und gefälschte `Remote-User`-/Forwarded-Header gewähren keinen Zugriff; der Dienst akzeptiert ausschließlich den Proxy.
- Erzeuge eine zeitlich und zahlenmäßig begrenzte Einladung. Löse sie mit einem eigenen synthetischen Konto ein, prüfe Passwortanmeldung, Gruppenzuweisung, Widerruf und Sperren. Werte aus dem Einladungslink und Passwörter vertraulich behandeln.
- Native Passwortänderung und gleichzeitige Administrationsänderung dürfen sich nicht gegenseitig überschreiben; Benutzerdatei, Berechtigungen und Testaufzeichnungen prüfen.
- 2FA-Registrierung und Richtlinien erscheinen derzeit absichtlich als „Unbekannt“; das ist keine Aussage über die tatsächliche MFA-Pflicht. Prüfe sie in Authelia.
- Die Benachrichtigungsarchiv-Endpunkte sind deaktiviert. Mailfreie Erstregistrierung ist **nicht** durch diese Benutzerverwaltung implementiert; dafür die offiziellen Authelia-Notifizierer im Labor getrennt prüfen.
- Neustart und Wiederherstellung aus Test-Backup nachweisen. Bestehende App-Sitzungen können nach Sperrung/Gruppenentzug weiter gültig sein; jeweilige Anwendung separat prüfen.

## Entfernen im Labor

Dienst stoppen und deaktivieren, zuvor angepasste Traefik- und Authelia-Regeln anhand der gesicherten Ausgangskonfiguration zurücknehmen und die Erreichbarkeit der normalen Anmeldung prüfen. Labordaten und temporäre Secrets nur innerhalb des zuvor eindeutig bestimmten Laborbereichs entfernen. Benutzer- und MFA-Datenbanken einer bestehenden Installation niemals mit einem alten Backup überschreiben, ohne die Folgen aktueller Änderungen geprüft zu haben.
