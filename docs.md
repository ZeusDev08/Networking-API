# Bienvenidos a la API sobre redes de la información de ByteDev (AKA Astrallity and ZeusDev08
Esta API es una API bastante especial, he añadido una calculadora IP que no está terminada aún y algunas herramientas de red como:
1. Sniffer
2. DNS Resolver
3. IP to DOMAIN Resolver
Entre otras cosas.

# INSTALACIÓN DE LA API
Para instalar esta API ejecutaremos el siguiente comando en nuestra consola:

```
git clone https://github.com/ZeusDev08/Networking-API.git
```


# Preparación del entorno
Bien, para esta API necesitamos un entorno en el que crearemos un archivo .env en el que pondremos nuestra AUTH_TOKEN de turso.tech

El archivo debería quedar como esto

```
AUTH_TOKEN = "TU_TOKEN"
```

# INSTALACIÓN REQUERIMIENTOS

Para instalar las librerías necesarias para ejecutar esta API usaremos el comando:

```
pip install -r requirements.txt
```

# EXPLICACIÓN DETALLADA DE TODOS LOS ENDPOINTS
Ahora explicaré que hace cada endpoint de mi API. Cabe destacar que requiere registrarse y loguearse dentro de la API para usar algunos endpoints.

## / Nada más entras devuelve un mensaje
El endpoint / es la raíz de toda la API es por así decirlo Home

## /api/v1/theory
Este endpoint requiere de login y token una vez obtenidos (La explicación de como obtener una token está mas abajo), este endpoint devuelve los archivos con una estructura HTML con 2 links descarga y ver:

![imatge](https://github.com/ZeusDev08/Networking-API/assets/100066830/3cc04ddf-3c60-44ae-9ff6-485b99387aa5)





