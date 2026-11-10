# Handover / offene Aufgaben

Stand: 10. November 2026. Das Repository ist ein **experimenteller Entwicklungsstand**, keine produktionsreife Installationsvorlage.

## Vorhanden

- Öffentliche README mit kopierbarem KI-Prompt, Funktionsgalerie und historischem Vergleich der Authelia-4.39.16-Kontoseite. Die Funktionsgalerie zeigt synthetische Daten; die geschwärzte Aufnahme der Kontoeinstellungen stammt aus einer echten Anmeldung.
- Separate Benutzerverwaltung für Einladungen, Konten und Gruppen. Die Version 4.39.16 des Patches ist historisch; ein experimenteller Port auf 4.39.28 und ein noch nicht gebautes OCI-Rezept liegen im Repository.
- Im isolierten Labor bestanden HTTPS, TOTP, Einladungserstellung/-einlösung und der Konfliktfall bei Gruppenänderungen; der Hash-Aufruf verwendete einen Testshim, keinen echten Docker-Socket. Die Ergebnisse beweisen keine Produktionsfreigabe.

## Wichtigste offene Punkte

- [ ] **Nicht produktiv einsetzen:** Der veröffentlichte experimentelle File-Lock-Port hat bei Dateifehlern nachweisbare Sicherheitsgrenzen. Der alternative Guard-Kandidat verbessert Teilfälle, deckt aber unter anderem Dateientfernung, OIDC-/App-Tokens, Wiederherstellung und mehrere Replikate nicht vollständig ab.
- [ ] Den nicht veröffentlichten Forschungsstand unabhängig prüfen: Zwischen Dateiaustausch und asynchronem Watcher-Reload kann eine veraltete Freigabe erfolgen. Ein experimenteller Ansatz für einen Abschlussabgleich unter gemeinsamer Sidecar-Sperre wurde begonnen, ist unvollständig und nicht freigegeben. Nicht automatisch von beobachtetem Einzeltest auf globale Sicherheit schließen.
- [ ] Authentifizierung, Berechtigungsentzug, gleichzeitige Schreiber, Fehler-/Neustartverhalten und getrennte Netzgrenzen mit synthetischen Daten reproduzierbar testen; bestehende Anwendungs-Tokens und alte Sitzungen separat behandeln.
- [ ] OCI-Image in einer geeigneten isolierten Buildumgebung tatsächlich bauen und mit echtem Docker-Hashpfad testen. Das vorhandene Rezept wurde noch nicht als Image gebaut oder freigegeben.
- [ ] Eine geprüfte Installations-, Backup- und Wiederherstellungsanleitung einschließlich mailfreier erster 2FA-Registrierung erstellen. Sichere Nutzerverwaltung darf erst nach unabhängiger Prüfung als einsatzbereit beschrieben werden.
- [ ] Änderungen an der historischen nativen Kontoseite für aktuelle Versionen separat portieren und prüfen; die Vergleichsbilder belegen nur Version 4.39.16.

## Verknüpfung

Die Proxmox-Musterlösung ist ein separates Projekt: https://github.com/WaldemarFech/meine-proxmox-musterloesung . Das Repository enthält eine KI-Kopiervorlage, eine Architektur-/Netzdokumentation mit realen Beispielwerten und geschwärzte echte Aufnahmen; ein vollständiger Installationsnachweis und Proxmox-GUI-Screenshots stehen noch aus.
