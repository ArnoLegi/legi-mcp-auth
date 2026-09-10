"""Validation d'un jeton d'accès Microsoft Entra ID (JWT v2.0).

Un contrôle omis ici est une porte ouverte. Sont vérifiés, dans cet ordre :

1. l'algorithme annoncé dans l'en-tête est RS256 — `none` et tout autre algorithme sont
   refusés AVANT toute autre opération (attaque classique : `alg: none`, ou substitution
   HS256 en utilisant la clé publique comme secret) ;
2. la signature, avec la clé publique du tenant désignée par `kid` ;
3. `iss` = https://login.microsoftonline.com/<tenant>/v2.0 ;
4. `aud` ∈ audiences acceptées (client ID nu ou `api://<client-id>`) ;
5. `exp` / `nbf`, avec 60 secondes de tolérance d'horloge ;
6. `tid` = tenant attendu — sans lui, un jeton d'un AUTRE annuaire Entra portant la
   bonne audience passerait (le fameux « everyone is an admin » multi-tenant) ;
7. `scp` contient la portée requise ;
8. `groups` recoupe les groupes autorisés, si la liste est configurée.

Le motif exact d'un refus reste ici et dans les journaux : la réponse HTTP, elle, ne dit
jamais pourquoi (un attaquant apprendrait quoi corriger à chaque essai).
"""
from __future__ import annotations

import logging
from typing import Any

import jwt

from .config import ParametresAuth
from .jwks import ALGORITHME, CacheJWKS, CleInconnue, JWKSIndisponible

log = logging.getLogger("legi_mcp_auth.validation")


class JetonRefuse(Exception):
    """Jeton rejeté. `motif` est destiné aux journaux, jamais à la réponse HTTP."""

    def __init__(self, motif: str) -> None:
        super().__init__(motif)
        self.motif = motif


class ValidateurEntra:
    """Valide les jetons d'accès émis par un tenant Entra ID donné."""

    def __init__(
        self,
        parametres: ParametresAuth,
        *,
        cache_jwks: CacheJWKS | None = None,
    ) -> None:
        self.parametres = parametres
        self.jwks = cache_jwks or CacheJWKS(parametres.url_jwks, ttl=parametres.jwks_ttl)

    async def valider(self, jeton: str) -> dict[str, Any]:
        """Renvoie les revendications du jeton, ou lève `JetonRefuse`."""
        p = self.parametres

        # 1. En-tête : algorithme et `kid`, avant toute vérification cryptographique.
        try:
            entete = jwt.get_unverified_header(jeton)
        except jwt.PyJWTError as exc:
            raise JetonRefuse(f"en-tête JWT illisible : {exc}") from exc

        algorithme = entete.get("alg")
        if algorithme != ALGORITHME:
            raise JetonRefuse(f"algorithme {algorithme!r} refusé (seul {ALGORITHME} est accepté)")

        # 2. Clé publique du tenant.
        try:
            cle = await self.jwks.cle(entete.get("kid", ""))
        except CleInconnue as exc:
            raise JetonRefuse(f"clé de signature inconnue : {exc}") from exc
        except JWKSIndisponible as exc:
            # Panne d'infrastructure, pas un jeton frauduleux : on refuse quand même
            # (fail closed), mais le journal doit permettre de distinguer les deux.
            log.error("Validation impossible, JWKS indisponible : %s", exc)
            raise JetonRefuse(f"JWKS indisponible : {exc}") from exc

        # 3 à 5. Signature, émetteur, audience, fenêtre temporelle.
        try:
            revendications: dict[str, Any] = jwt.decode(
                jeton,
                key=cle,
                algorithms=[ALGORITHME],
                audience=list(p.audiences_acceptees),
                issuer=p.issuer,
                leeway=p.tolerance_horloge,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise JetonRefuse("jeton expiré") from exc
        except jwt.ImmatureSignatureError as exc:
            raise JetonRefuse("jeton pas encore valide (nbf)") from exc
        except jwt.InvalidAudienceError as exc:
            raise JetonRefuse(f"audience invalide (attendu {p.audiences_acceptees})") from exc
        except jwt.InvalidIssuerError as exc:
            raise JetonRefuse(f"émetteur invalide (attendu {p.issuer})") from exc
        except jwt.PyJWTError as exc:
            raise JetonRefuse(f"jeton invalide : {type(exc).__name__}: {exc}") from exc

        # 6. Annuaire d'origine.
        tid = revendications.get("tid")
        if tid != p.tenant_id:
            raise JetonRefuse(f"tid={tid!r} étranger au tenant attendu")

        # 7. Portée déléguée.
        portees = str(revendications.get("scp") or "").split()
        if p.scope_requis not in portees:
            raise JetonRefuse(f"portée {p.scope_requis!r} absente (scp={portees})")

        # 8. Appartenance à un groupe autorisé.
        if p.groupes_autorises:
            groupes = revendications.get("groups") or []
            if isinstance(groupes, str):
                groupes = [groupes]
            if not set(groupes) & set(p.groupes_autorises):
                # Cas piège : au-delà de ~200 groupes, Entra remplace `groups` par une
                # revendication `_claim_names` renvoyant vers Graph. Le jeton est alors
                # refusé, et le journal doit le dire clairement.
                if "_claim_names" in revendications or "_claim_sources" in revendications:
                    raise JetonRefuse(
                        "revendication `groups` remplacée par une référence Graph "
                        "(utilisateur membre de trop de groupes) : configurez "
                        "l'application pour n'émettre que les groupes assignés"
                    )
                raise JetonRefuse("aucun groupe autorisé dans la revendication `groups`")

        return revendications


def utilisateur_depuis_revendications(revendications: dict[str, Any]) -> dict[str, Any]:
    """Identité exposée à l'application : le strict nécessaire à l'audit."""
    return {
        "oid": revendications.get("oid"),
        "preferred_username": revendications.get("preferred_username"),
        "name": revendications.get("name"),
    }
