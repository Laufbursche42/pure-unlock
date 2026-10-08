# Anleitung

> **Wichtig für Fehler-Reports:** Schalte unten auf der Seite den **Diagnose-Log** ein, *bevor* du dich mit dem Scooter verbindest. Nur dann wird der komplette Verbindungsaufbau mitgeschnitten - und genau diese Zeilen brauchen wir in einem [Ticket](https://github.com/Laufbursche42/Laufbursche42/issues), um ein Problem nachzuvollziehen.

## Was du brauchst
- Einen PURE E-Scooter (ZYD / HobbyWing-ESC).
- Ein Handy oder einen Rechner mit **Chrome**, **Edge** oder auf iOS **Bluefy**. Safari und Firefox können kein Web Bluetooth.

## Verbinden
1. Bluetooth am Gerät einschalten, den Scooter einschalten (wecken).
2. Auf **Verbinden** tippen und den Scooter in der Liste auswählen.
3. Taucht er nicht auf, setze den Haken bei **Alle Geräte zeigen** und verbinde erneut. Der echte Test ist der gefundene Bluetooth-Dienst (0xF1F0), nicht der angezeigte Name.
4. Verlangt dein Gerät ein Passwort (im Live-Feld steht TYPE B), gib die PIN im Feld **PIN** ein und tippe **PIN senden**. Die PIN läuft als Klartext über Bluetooth, es gibt keine Verschlüsselung.
5. Nach dem Verbinden erscheinen die Karten für Live-Werte, Sperre, Geschwindigkeit und Einstellungen.

## Live-Werte lesen
Aus dem AT-Kanal werden Passwort-Status, Gerätetyp, Antriebsmodus, NFC, Blinker-Ton und LUDO ausgelesen. Jede Kachel erscheint, sobald ihr Wert angekommen ist. Die Fahrtelemetrie (Tempo, Akku, Strom, Temperatur, Kilometer) sendet der Scooter laufend über den Binärkanal. Die Seite zeigt diese Daten als rohe Frames unter **Alle empfangenen Binär-Frames**.

## Geschwindigkeit setzen
- **Entsperren** schreibt den Wert aus dem Feld **Offen**, **Sperren** den Wert aus **eKFV / legal** ins Limit-Register (Adresse 32, Wert mal zehn, RW-Parameter 0x17).
- Mit **Genau setzen** schreibst du einen beliebigen km/h-Wert direkt. Das Register erlaubt bis 60.
- Wichtig: Ein Echo im Log heißt nur, dass der Scooter das Frame angenommen hat. Das Limit lässt sich nicht zurücklesen, also zeigt erst das Verhalten am Gerät, dass der Wert wirkt.

## Sperre
In der Karte **Sperre** sperrst oder entsperrst du den Scooter (Immobilizer). Achtung: Die Sperre sitzt im selben 0xAB-Frame wie Licht, Gang, Tempomat und Einheit. Da sich der aktuelle Zustand nicht zurücklesen lässt, schreibt die Sperre das komplette Einstellungs-Frame aus den zuletzt gewählten Werten mit. Einen gesperrten Scooter kannst du nur über Bluetooth wieder entsperren.

## Weitere Einstellungen
- **AT-Schalter** (NFC, Blinker-Ton, Antriebsmodus, LUDO) werden einzeln geschrieben.
- **0xAB-Felder** (Scheinwerfer, Ambientelicht, Tempomat, Anfahrmodus, Einheit, Gang) teilen sich EIN Frame. Jedes Setzen schreibt alle diese Felder gemeinsam aus den zuletzt gewählten Werten. Prüfe die anderen Felder, bevor du sendest.
- **Radgröße** und **Modulationstiefe** gehen als RW-Parameter und sind riskant. Die Radgröße ändert nur die Tacho-Berechnung, nicht die reale Geschwindigkeit.

## Erweiterte Einstellungen (Engine-Ebene)
**Rohes Frame** sendet deine Hex-Bytes unverändert auf dem gewählten Kanal (DATA binär oder CMD/AT). **ESC-Frame bauen** nimmt Opcode und Payload und ergänzt Kopf 0x01 und CRC16/MODBUS selbst. **AT-Befehl** schickt eine ASCII-Zeile wie AT+NFC? auf den CMD-Kanal.

## Shortcuts
Kopiere den Link auf den Startbildschirm, dann ent- oder sperrt ein Tipp direkt. Auf iOS über Bluefy, und der Scooter muss vorher einmal normal verbunden gewesen sein.

## Wenn etwas nicht geht
- Kein Verbinden? Prüfe, dass der Browser Web Bluetooth kann, Bluetooth an ist und der Scooter wach ist. Mit **Alle Geräte zeigen** erneut versuchen.
- Nichts passiert nach einem Befehl? Schau ins Log: steht dort "gesendet" aber kein "bestätigt", hat die Firmware das Frame nicht quittiert.
- Passwort wird abgelehnt (OK+PWD:N)? Prüfe die PIN. Steht TYPE A, braucht das Gerät gar kein Passwort.
- **Diagnose: alle Geräte auflisten** im Log-Bereich zeigt alle Bluetooth-Dienste eines Geräts, ohne etwas zu schreiben - hilfreich für Support.

## Mithelfen
Willst du herausfinden, ob und wie Tuning bei deinem Scooter geht? Teste dieses Tool an deinem eigenen Fahrzeug und öffne ein Ticket auf [GitHub](https://github.com/Laufbursche42/Laufbursche42/issues) - mit deinem Modell und was funktioniert hat (oder nicht). So finden wir gemeinsam heraus, was bei welchem Modell möglich ist.
