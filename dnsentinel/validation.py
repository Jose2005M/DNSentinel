"""Validación positiva de entradas en el servidor, independiente del navegador."""
import ipaddress
import re


class InvalidInput(ValueError):
    """Entrada rechazada con un mensaje público controlado."""


def domain_name(value):
    if not isinstance(value, str) or len(value) > 254:
        raise InvalidInput('El dominio debe ser texto de hasta 253 caracteres.')
    domain = value.strip().lower().removesuffix('.')
    labels = domain.split('.')
    if (len(domain) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in labels)):
        raise InvalidInput('Escribe un dominio válido sin protocolo, puerto ni rutas. Usa punycode para nombres internacionales.')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise InvalidInput('Introduce un dominio, no una dirección IP.')


def object_fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys():
        raise InvalidInput('Faltan campos obligatorios o el cuerpo JSON no es válido.')
    if value.keys() - set(required) - set(optional):
        raise InvalidInput('La solicitud contiene campos no admitidos.')
    return value


def rule_input(value):
    data = object_fields(value, ('domain', 'kind', 'note', 'subdomains', 'active'))
    if data['kind'] not in ('block', 'allow'):
        raise InvalidInput('La acción debe ser block o allow.')
    if type(data['subdomains']) is not bool or type(data['active']) is not bool:
        raise InvalidInput('El estado y la opción de subdominios deben ser booleanos.')
    if (not isinstance(data['note'], str) or len(data['note']) > 120 or
            any(ord(c) < 32 or ord(c) == 127 for c in data['note'])):
        raise InvalidInput('La descripción admite hasta 120 caracteres sin controles ni saltos de línea.')
    return {**data, 'domain': domain_name(data['domain']), 'note': data['note'].strip()}


def username(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{3,40}', value):
        raise InvalidInput('El usuario debe tener entre 3 y 40 letras, números, puntos, guiones o guiones bajos.')
    return value.lower()


def password_policy(value):
    if not isinstance(value, str) or not 15 <= len(value) <= 128:
        raise InvalidInput('Usa una contraseña o frase de entre 15 y 128 caracteres.')
    return value
