/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.tools.democonfig;

import java.util.List;
import java.util.function.Supplier;

/**
 * Enum for demo certificates
 */
public enum Certificates {
    ADMIN_CERT(
        "kirk.pem",
        () -> getCertContent(
            List.of(
                "-----BEGIN CERTIFICATE-----",
                "MIIEmDCCA4CgAwIBAgIUaYSlET3nzsotWTrWueVPPh10yLcwDQYJKoZIhvcNAQEL",
                "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt",
                "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl",
                "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v",
                "dCBDQTAeFw0yNDAyMjAxNzA0MjRaFw0zNDAyMTcxNzA0MjRaME0xCzAJBgNVBAYT",
                "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ8wDQYDVQQKDAZjbGllbnQxDzANBgNVBAsMBmNs",
                "aWVudDENMAsGA1UEAwwEa2lyazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC",
                "ggEBAJVcOAQlCiuB9emCljROAXnlsPbG7PE3kNz2sN+BbGuw686Wgyl3uToVHvVs",
                "paMmLUqm1KYz9wMSWTIBZgpJ9hYaIbGxD4RBb7qTAJ8Q4ddCV2f7T4lxao/6ixI+",
                "O0l/BG9E3mRGo/r0w+jtTQ3aR2p6eoxaOYbVyEMYtFI4QZTkcgGIPGxm05y8xonx",
                "vV5pbSW9L7qAVDzQC8EYGQMMI4ccu0NcHKWtmTYJA/wDPE2JwhngHwbcIbc4cDz6",
                "cG0S3FmgiKGuuSqUy35v/k3y7zMHQSdx7DSR2tzhH/bBL/9qGvpT71KKrxPtaxS0",
                "bAqPcEkKWDo7IMlGGW7LaAWfGg8CAwEAAaOCASswggEnMAwGA1UdEwEB/wQCMAAw",
                "DgYDVR0PAQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMB0GA1UdDgQW",
                "BBSjMS8tgguX/V7KSGLoGg7K6XMzIDCBzwYDVR0jBIHHMIHEgBQXh9+gWutmEqfV",
                "0Pi6EkU8tysAnKGBlaSBkjCBjzETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmS",
                "JomT8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1wbGUgQ29tIEluYy4xITAf",
                "BgNVBAsMGEV4YW1wbGUgQ29tIEluYy4gUm9vdCBDQTEhMB8GA1UEAwwYRXhhbXBs",
                "ZSBDb20gSW5jLiBSb290IENBghQNZAmZZn3EFOxBR4630XlhI+mo4jANBgkqhkiG",
                "9w0BAQsFAAOCAQEACEUPPE66/Ot3vZqRGpjDjPHAdtOq+ebaglQhvYcnDw8LOZm8",
                "Gbh9M88CiO6UxC8ipQLTPh2yyeWArkpJzJK/Pi1eoF1XLiAa0sQ/RaJfQWPm9dvl",
                "1ZQeK5vfD4147b3iBobwEV+CR04SKow0YeEEzAJvzr8YdKI6jqr+2GjjVqzxvRBy",
                "KRVHWCFiR7bZhHGLq3br8hSu0hwjb3oGa1ZI8dui6ujyZt6nm6BoEkau3G/6+zq9",
                "E6vX3+8Fj4HKCAL6i0SwfGmEpTNp5WUhqibK/fMhhmMT4Mx6MxkT+OFnIjdUU0S/",
                "e3kgnG8qjficUr38CyEli1U0M7koIXUZI7r+LQ==",
                "-----END CERTIFICATE-----"
            )
        )
    ),
    ADMIN_CERT_KEY(
        "kirk-key.pem",
        () -> getCertContent(
            List.of(
                "-----BEGIN PRIVATE KEY-----",
                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVXDgEJQorgfXp",
                "gpY0TgF55bD2xuzxN5Dc9rDfgWxrsOvOloMpd7k6FR71bKWjJi1KptSmM/cDElky",
                "AWYKSfYWGiGxsQ+EQW+6kwCfEOHXQldn+0+JcWqP+osSPjtJfwRvRN5kRqP69MPo",
                "7U0N2kdqenqMWjmG1chDGLRSOEGU5HIBiDxsZtOcvMaJ8b1eaW0lvS+6gFQ80AvB",
                "GBkDDCOHHLtDXBylrZk2CQP8AzxNicIZ4B8G3CG3OHA8+nBtEtxZoIihrrkqlMt+",
                "b/5N8u8zB0Encew0kdrc4R/2wS//ahr6U+9Siq8T7WsUtGwKj3BJClg6OyDJRhlu",
                "y2gFnxoPAgMBAAECggEAP5TOycDkx+megAWVoHV2fmgvgZXkBrlzQwUG/VZQi7V4",
                "ZGzBMBVltdqI38wc5MtbK3TCgHANnnKgor9iq02Z4wXDwytPIiti/ycV9CDRKvv0",
                "TnD2hllQFjN/IUh5n4thHWbRTxmdM7cfcNgX3aZGkYbLBVVhOMtn4VwyYu/Mxy8j",
                "xClZT2xKOHkxqwmWPmdDTbAeZIbSv7RkIGfrKuQyUGUaWhrPslvYzFkYZ0umaDgQ",
                "OAthZew5Bz3OfUGOMPLH61SVPuJZh9zN1hTWOvT65WFWfsPd2yStI+WD/5PU1Doo",
                "1RyeHJO7s3ug8JPbtNJmaJwHe9nXBb/HXFdqb976yQKBgQDNYhpu+MYSYupaYqjs",
                "9YFmHQNKpNZqgZ4ceRFZ6cMJoqpI5dpEMqToFH7tpor72Lturct2U9nc2WR0HeEs",
                "/6tiptyMPTFEiMFb1opQlXF2ae7LeJllntDGN0Q6vxKnQV+7VMcXA0Y8F7tvGDy3",
                "qJu5lfvB1mNM2I6y/eMxjBuQhwKBgQC6K41DXMFro0UnoO879pOQYMydCErJRmjG",
                "/tZSy3Wj4KA/QJsDSViwGfvdPuHZRaG9WtxdL6kn0w1exM9Rb0bBKl36lvi7o7xv",
                "M+Lw9eyXMkww8/F5d7YYH77gIhGo+RITkKI3+5BxeBaUnrGvmHrpmpgRXWmINqr0",
                "0jsnN3u0OQKBgCf45vIgItSjQb8zonLz2SpZjTFy4XQ7I92gxnq8X0Q5z3B+o7tQ",
                "K/4rNwTju/sGFHyXAJlX+nfcK4vZ4OBUJjP+C8CTjEotX4yTNbo3S6zjMyGQqDI5",
                "9aIOUY4pb+TzeUFJX7If5gR+DfGyQubvvtcg1K3GHu9u2l8FwLj87sRzAoGAflQF",
                "RHuRiG+/AngTPnZAhc0Zq0kwLkpH2Rid6IrFZhGLy8AUL/O6aa0IGoaMDLpSWUJp",
                "nBY2S57MSM11/MVslrEgGmYNnI4r1K25xlaqV6K6ztEJv6n69327MS4NG8L/gCU5",
                "3pEm38hkUi8pVYU7in7rx4TCkrq94OkzWJYurAkCgYATQCL/rJLQAlJIGulp8s6h",
                "mQGwy8vIqMjAdHGLrCS35sVYBXG13knS52LJHvbVee39AbD5/LlWvjJGlQMzCLrw",
                "F7oILW5kXxhb8S73GWcuMbuQMFVHFONbZAZgn+C9FW4l7XyRdkrbR1MRZ2km8YMs",
                "/AHmo368d4PSNRMMzLHw8Q==",
                "-----END PRIVATE KEY-----"
            )
        )
    ),
    NODE_CERT(
        "esnode.pem",
        () -> getCertContent(
            List.of(
                "-----BEGIN CERTIFICATE-----",
                "MIIEPDCCAySgAwIBAgIUaYSlET3nzsotWTrWueVPPh10yLYwDQYJKoZIhvcNAQEL",
                "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt",
                "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl",
                "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v",
                "dCBDQTAeFw0yNDAyMjAxNzAzMjVaFw0zNDAyMTcxNzAzMjVaMFcxCzAJBgNVBAYT",
                "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ0wCwYDVQQKDARub2RlMQ0wCwYDVQQLDARub2Rl",
                "MRswGQYDVQQDDBJub2RlLTAuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA",
                "A4IBDwAwggEKAoIBAQCm93kXteDQHMAvbUPNPW5pyRHKDD42XGWSgq0k1D29C/Ud",
                "yL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0",
                "HGkn47XVu3EwbfrTENg3jFu+Oem6a/501SzITzJWtS0cn2dIFOBimTVpT/4Zv5qr",
                "XA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8n",
                "dibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b6l+KLo3IKpfTbAIJXIO+M67FLtWKtttD",
                "ao94B069skzKk6FPgW/OZh6PRCD0oxOavV+ld2SjAgMBAAGjgcYwgcMwRwYDVR0R",
                "BEAwPogFKgMEBQWCEm5vZGUtMC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hxAAAAAA",
                "AAAAAAAAAAAAAAABhwR/AAABMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEF",
                "BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU0/qDQaY10jIo",
                "wCjLUpz/HfQXyt8wHwYDVR0jBBgwFoAUF4ffoFrrZhKn1dD4uhJFPLcrAJwwDQYJ",
                "KoZIhvcNAQELBQADggEBAGbij5WyF0dKhQodQfTiFDb73ygU6IyeJkFSnxF67gDz",
                "pQJZKFvXuVBa3cGP5e7Qp3TK50N+blXGH0xXeIV9lXeYUk4hVfBlp9LclZGX8tGi",
                "7Xa2enMvIt5q/Yg3Hh755ZxnDYxCoGkNOXUmnMusKstE0YzvZ5Gv6fcRKFBUgZLh",
                "hUBqIEAYly1EqH/y45APiRt3Nor1yF6zEI4TnL0yNrHw6LyQkUNCHIGMJLfnJQ9L",
                "camMGIXOx60kXNMTigF9oXXwixWAnDM9y3QT8QXA7hej/4zkbO+vIeV/7lGUdkyg",
                "PAi92EvyxmsliEMyMR0VINl8emyobvfwa7oMeWMR+hg=",
                "-----END CERTIFICATE-----"
            )
        )
    ),
    NODE_KEY(
        "esnode-key.pem",
        () -> getCertContent(
            List.of(
                "-----BEGIN PRIVATE KEY-----",
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm93kXteDQHMAv",
                "bUPNPW5pyRHKDD42XGWSgq0k1D29C/UdyL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0",
                "o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0HGkn47XVu3EwbfrTENg3jFu+Oem6a/50",
                "1SzITzJWtS0cn2dIFOBimTVpT/4Zv5qrXA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1",
                "MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8ndibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b",
                "6l+KLo3IKpfTbAIJXIO+M67FLtWKtttDao94B069skzKk6FPgW/OZh6PRCD0oxOa",
                "vV+ld2SjAgMBAAECggEAQK1+uAOZeaSZggW2jQut+MaN4JHLi61RH2cFgU3COLgo",
                "FIiNjFn8f2KKU3gpkt1It8PjlmprpYut4wHI7r6UQfuv7ZrmncRiPWHm9PB82+ZQ",
                "5MXYqj4YUxoQJ62Cyz4sM6BobZDrjG6HHGTzuwiKvHHkbsEE9jQ4E5m7yfbVvM0O",
                "zvwrSOM1tkZihKSTpR0j2+taji914tjBssbn12TMZQL5ItGnhR3luY8mEwT9MNkZ",
                "xg0VcREoAH+pu9FE0vPUgLVzhJ3be7qZTTSRqv08bmW+y1plu80GbppePcgYhEow",
                "dlW4l6XPJaHVSn1lSFHE6QAx6sqiAnBz0NoTPIaLyQKBgQDZqDOlhCRciMRicSXn",
                "7yid9rhEmdMkySJHTVFOidFWwlBcp0fGxxn8UNSBcXdSy7GLlUtH41W9PWl8tp9U",
                "hQiiXORxOJ7ZcB80uNKXF01hpPj2DpFPWyHFxpDkWiTAYpZl68rOlYujxZUjJIej",
                "VvcykBC2BlEOG9uZv2kxcqLyJwKBgQDEYULTxaTuLIa17wU3nAhaainKB3vHxw9B",
                "Ksy5p3ND43UNEKkQm7K/WENx0q47TA1mKD9i+BhaLod98mu0YZ+BCUNgWKcBHK8c",
                "uXpauvM/pLhFLXZ2jvEJVpFY3J79FSRK8bwE9RgKfVKMMgEk4zOyZowS8WScOqiy",
                "hnQn1vKTJQKBgElhYuAnl9a2qXcC7KOwRsJS3rcKIVxijzL4xzOyVShp5IwIPbOv",
                "hnxBiBOH/JGmaNpFYBcBdvORE9JfA4KMQ2fx53agfzWRjoPI1/7mdUk5RFI4gRb/",
                "A3jZRBoopgFSe6ArCbnyQxzYzToG48/Wzwp19ZxYrtUR4UyJct6f5n27AoGBAJDh",
                "KIpQQDOvCdtjcbfrF4aM2DPCfaGPzENJriwxy6oEPzDaX8Bu/dqI5Ykt43i/zQrX",
                "GpyLaHvv4+oZVTiI5UIvcVO9U8hQPyiz9f7F+fu0LHZs6f7hyhYXlbe3XFxeop3f",
                "5dTKdWgXuTTRF2L9dABkA2deS9mutRKwezWBMQk5AoGBALPtX0FrT1zIosibmlud",
                "tu49A/0KZu4PBjrFMYTSEWGNJez3Fb2VsJwylVl6HivwbP61FhlYfyksCzQQFU71",
                "+x7Nmybp7PmpEBECr3deoZKQ/acNHn0iwb0It+YqV5+TquQebqgwK6WCLsMuiYKT",
                "bg/ch9Rhxbq22yrVgWHh6epp",
                "-----END PRIVATE KEY-----"
            )
        )
    ),
    ROOT_CA(
        "root-ca.pem",
        () -> getCertContent(
            List.of(
                "-----BEGIN CERTIFICATE-----",
                "MIIExjCCA66gAwIBAgIUDWQJmWZ9xBTsQUeOt9F5YSPpqOIwDQYJKoZIhvcNAQEL",
                "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt",
                "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl",
                "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v",
                "dCBDQTAeFw0yNDAyMjAxNzAwMzZaFw0zNDAyMTcxNzAwMzZaMIGPMRMwEQYKCZIm",
                "iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ",
                "RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290",
                "IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwggEiMA0GCSqG",
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEPyN7J9VGPyJcQmCBl5TGwfSzvVdWwoQU",
                "j9aEsdfFJ6pBCDQSsj8Lv4RqL0dZra7h7SpZLLX/YZcnjikrYC+rP5OwsI9xEE/4",
                "U98CsTBPhIMgqFK6SzNE5494BsAk4cL72dOOc8tX19oDS/PvBULbNkthQ0aAF1dg",
                "vbrHvu7hq7LisB5ZRGHVE1k/AbCs2PaaKkn2jCw/b+U0Ml9qPuuEgz2mAqJDGYoA",
                "WSR4YXrOcrmPuRqbws464YZbJW898/0Pn/U300ed+4YHiNYLLJp51AMkR4YEw969",
                "VRPbWIvLrd0PQBooC/eLrL6rvud/GpYhdQEUx8qcNCKd4bz3OaQ5AgMBAAGjggEW",
                "MIIBEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU",
                "F4ffoFrrZhKn1dD4uhJFPLcrAJwwgc8GA1UdIwSBxzCBxIAUF4ffoFrrZhKn1dD4",
                "uhJFPLcrAJyhgZWkgZIwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ",
                "k/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYD",
                "VQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUg",
                "Q29tIEluYy4gUm9vdCBDQYIUDWQJmWZ9xBTsQUeOt9F5YSPpqOIwDQYJKoZIhvcN",
                "AQELBQADggEBAL3Q3AHUhMiLUy6OlLSt8wX9I2oNGDKbBu0atpUNDztk/0s3YLQC",
                "YuXgN4KrIcMXQIuAXCx407c+pIlT/T1FNn+VQXwi56PYzxQKtlpoKUL3oPQE1d0V",
                "6EoiNk+6UodvyZqpdQu7fXVentRMk1QX7D9otmiiNuX+GSxJhJC2Lyzw65O9EUgG",
                "1yVJon6RkUGtqBqKIuLksKwEr//ELnjmXit4LQKSnqKr0FTCB7seIrKJNyb35Qnq",
                "qy9a/Unhokrmdda1tr6MbqU8l7HmxLuSd/Ky+L0eDNtYv6YfMewtjg0TtAnFyQov",
                "rdXmeq1dy9HLo3Ds4AFz3Gx9076TxcRS/iI=",
                "-----END CERTIFICATE-----"
            )
        )
    );

    private final String fileName;
    private final Supplier<String> contentSupplier;

    Certificates(String fileName, Supplier<String> contentSupplier) {
        this.fileName = fileName;
        this.contentSupplier = contentSupplier;
    }

    public String getFileName() {
        return fileName;
    }

    public String getContent() {
        return contentSupplier.get();
    }

    private static String getCertContent(List<String> certLines) {
        return String.join(System.lineSeparator(), certLines);
    }
}
