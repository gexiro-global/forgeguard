# 06 Przeglad (SELF_REVIEW) - wydanie 0.6.0

SELF_REVIEW. Control Plane Hardening: nowy modul forgeguard/runner_review.py (offline,
zero-network, 8 checkow FG-RUNNER-*), nowy schemat forgeguard.runner-snapshot.v1,
dodatkowe pola RunnerInfo w providers/base.py+gitea.py+forgejo.py (addytywne, bez zmiany
istniejacej semantyki scan/config-review). Pelna kwalifikacja G01-G15 na dokladnych
finalnych paczkach 0.6.0 z zaufanego run 34619892271/1 (zrodlo ea589c6, branch
feat/forgeguard-v0.6-control-plane-hardening): 383 testy x2 (py3.11/3.12, w tym 27
nowych testow runner_review), coverage 95.58% (wymagane 91.28%), 16/16 realnych
wariantow HTTP integration lab (Gitea 1.26.4/1.27.3, Forgejo 15.0.8/16.0.4, dokladnie
te same obrazy Docker co przy 0.5.0), 2/2 TLS/subpath, instalacje wheel/sdist poza
checkoutem (obie funkcjonalne, w tym realny `forgeguard runner review` przeciw
examples/forgejo-runner-snapshot.json = A/100), SBOM+audyt pip-audit swiezo
wygenerowane dla srodowisk runtime(19)/dev(52)/build(2) - 0 podatnosci we wszystkich,
skan sekretow (detect-secrets) bez nowych realnych trafien (34 wpisy to znany szum
golden-fixture/hash w przykladach i evidence, nie prawdziwe sekrety), attestacja z
realnego joba candidate-provenance tego samego runu zweryfikowana niezaleznie.
Akceptacja wlasciciela i decyzja o wydaniu byly udzielone explicite w tym zadaniu
(dokument FORGEGUARD_OPUS_ONE_SHOT_0_6_0_CONTROL_PLANE_HARDENING).

Rzeczywiste luki znalezione i naprawione PRZED wydaniem (nie ukryte): (1) ci.yml gate
na candidate-provenance/qualification-evidence byl zawezony do brancha 0.5.0 -
poprawione w PR #22 (ea589c6) PRZED tagiem, wiec run 34619892271 faktycznie
wyprodukowal te artefakty; (2) statyczne pliki qualification/evidence/* zastane po
mergu F02 z poprzedniej rundy byly z 0.5.0 (356 testow, zla rewizja) - w tej rundzie
CALY zestaw 16 kategorii zostal swiezo wygenerowany z prawdziwych narzedzi
(tools.integration_lab, tools.tls_lab, pip-audit, cyclonedx-py, detect-secrets,
rzeczywisty gh attestation verify z CI) przeciw dokladnie tym bajtom kandydata
0.6.0, zamiast bycia po cichu skopiowanym.
