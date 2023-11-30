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

/**
 * Enum for demo certificates
 */
public enum Certificates {
    ADMIN_CERT(
        "kirk.pem",
        "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "MIIEmDCCA4CgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iYwDQYJKoZIhvcNAQEL"
            + System.lineSeparator()
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt"
            + System.lineSeparator()
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl"
            + System.lineSeparator()
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v"
            + System.lineSeparator()
            + "dCBDQTAeFw0yMzA4MjkyMDA2MzdaFw0zMzA4MjYyMDA2MzdaME0xCzAJBgNVBAYT"
            + System.lineSeparator()
            + "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ8wDQYDVQQKDAZjbGllbnQxDzANBgNVBAsMBmNs"
            + System.lineSeparator()
            + "aWVudDENMAsGA1UEAwwEa2lyazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC"
            + System.lineSeparator()
            + "ggEBAJVcOAQlCiuB9emCljROAXnlsPbG7PE3kNz2sN+BbGuw686Wgyl3uToVHvVs"
            + System.lineSeparator()
            + "paMmLUqm1KYz9wMSWTIBZgpJ9hYaIbGxD4RBb7qTAJ8Q4ddCV2f7T4lxao/6ixI+"
            + System.lineSeparator()
            + "O0l/BG9E3mRGo/r0w+jtTQ3aR2p6eoxaOYbVyEMYtFI4QZTkcgGIPGxm05y8xonx"
            + System.lineSeparator()
            + "vV5pbSW9L7qAVDzQC8EYGQMMI4ccu0NcHKWtmTYJA/wDPE2JwhngHwbcIbc4cDz6"
            + System.lineSeparator()
            + "cG0S3FmgiKGuuSqUy35v/k3y7zMHQSdx7DSR2tzhH/bBL/9qGvpT71KKrxPtaxS0"
            + System.lineSeparator()
            + "bAqPcEkKWDo7IMlGGW7LaAWfGg8CAwEAAaOCASswggEnMAwGA1UdEwEB/wQCMAAw"
            + System.lineSeparator()
            + "DgYDVR0PAQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMIHPBgNVHSME"
            + System.lineSeparator()
            + "gccwgcSAFBeH36Ba62YSp9XQ+LoSRTy3KwCcoYGVpIGSMIGPMRMwEQYKCZImiZPy"
            + System.lineSeparator()
            + "LGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQRXhh"
            + System.lineSeparator()
            + "bXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENB"
            + System.lineSeparator()
            + "MSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0GCFHfkrz782p+T9k0G"
            + System.lineSeparator()
            + "xGeM4+BrehWKMB0GA1UdDgQWBBSjMS8tgguX/V7KSGLoGg7K6XMzIDANBgkqhkiG"
            + System.lineSeparator()
            + "9w0BAQsFAAOCAQEANMwD1JYlwAh82yG1gU3WSdh/tb6gqaSzZK7R6I0L7slaXN9m"
            + System.lineSeparator()
            + "y2ErUljpTyaHrdiBFmPhU/2Kj2r+fIUXtXdDXzizx/JdmueT0nG9hOixLqzfoC9p"
            + System.lineSeparator()
            + "fAhZxM62RgtyZoaczQN82k1/geMSwRpEndFe3OH7arkS/HSbIFxQhAIy229eWe5d"
            + System.lineSeparator()
            + "1bUzP59iu7f3r567I4ob8Vy7PP+Ov35p7Vv4oDHHwgsdRzX6pvL6mmwVrQ3BfVec"
            + System.lineSeparator()
            + "h9Dqprr+ukYmjho76g6k5cQuRaB6MxqldzUg+2E7IHQP8MCF+co51uZq2nl33mtp"
            + System.lineSeparator()
            + "RGr6JbdHXc96zsLTL3saJQ8AWEfu1gbTVrwyRA=="
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
    ),
    ADMIN_CERT_KEY(
        "kirk-key.pem",
        "-----BEGIN PRIVATE KEY-----"
            + System.lineSeparator()
            + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVXDgEJQorgfXp"
            + System.lineSeparator()
            + "gpY0TgF55bD2xuzxN5Dc9rDfgWxrsOvOloMpd7k6FR71bKWjJi1KptSmM/cDElky"
            + System.lineSeparator()
            + "AWYKSfYWGiGxsQ+EQW+6kwCfEOHXQldn+0+JcWqP+osSPjtJfwRvRN5kRqP69MPo"
            + System.lineSeparator()
            + "7U0N2kdqenqMWjmG1chDGLRSOEGU5HIBiDxsZtOcvMaJ8b1eaW0lvS+6gFQ80AvB"
            + System.lineSeparator()
            + "GBkDDCOHHLtDXBylrZk2CQP8AzxNicIZ4B8G3CG3OHA8+nBtEtxZoIihrrkqlMt+"
            + System.lineSeparator()
            + "b/5N8u8zB0Encew0kdrc4R/2wS//ahr6U+9Siq8T7WsUtGwKj3BJClg6OyDJRhlu"
            + System.lineSeparator()
            + "y2gFnxoPAgMBAAECggEAP5TOycDkx+megAWVoHV2fmgvgZXkBrlzQwUG/VZQi7V4"
            + System.lineSeparator()
            + "ZGzBMBVltdqI38wc5MtbK3TCgHANnnKgor9iq02Z4wXDwytPIiti/ycV9CDRKvv0"
            + System.lineSeparator()
            + "TnD2hllQFjN/IUh5n4thHWbRTxmdM7cfcNgX3aZGkYbLBVVhOMtn4VwyYu/Mxy8j"
            + System.lineSeparator()
            + "xClZT2xKOHkxqwmWPmdDTbAeZIbSv7RkIGfrKuQyUGUaWhrPslvYzFkYZ0umaDgQ"
            + System.lineSeparator()
            + "OAthZew5Bz3OfUGOMPLH61SVPuJZh9zN1hTWOvT65WFWfsPd2yStI+WD/5PU1Doo"
            + System.lineSeparator()
            + "1RyeHJO7s3ug8JPbtNJmaJwHe9nXBb/HXFdqb976yQKBgQDNYhpu+MYSYupaYqjs"
            + System.lineSeparator()
            + "9YFmHQNKpNZqgZ4ceRFZ6cMJoqpI5dpEMqToFH7tpor72Lturct2U9nc2WR0HeEs"
            + System.lineSeparator()
            + "/6tiptyMPTFEiMFb1opQlXF2ae7LeJllntDGN0Q6vxKnQV+7VMcXA0Y8F7tvGDy3"
            + System.lineSeparator()
            + "qJu5lfvB1mNM2I6y/eMxjBuQhwKBgQC6K41DXMFro0UnoO879pOQYMydCErJRmjG"
            + System.lineSeparator()
            + "/tZSy3Wj4KA/QJsDSViwGfvdPuHZRaG9WtxdL6kn0w1exM9Rb0bBKl36lvi7o7xv"
            + System.lineSeparator()
            + "M+Lw9eyXMkww8/F5d7YYH77gIhGo+RITkKI3+5BxeBaUnrGvmHrpmpgRXWmINqr0"
            + System.lineSeparator()
            + "0jsnN3u0OQKBgCf45vIgItSjQb8zonLz2SpZjTFy4XQ7I92gxnq8X0Q5z3B+o7tQ"
            + System.lineSeparator()
            + "K/4rNwTju/sGFHyXAJlX+nfcK4vZ4OBUJjP+C8CTjEotX4yTNbo3S6zjMyGQqDI5"
            + System.lineSeparator()
            + "9aIOUY4pb+TzeUFJX7If5gR+DfGyQubvvtcg1K3GHu9u2l8FwLj87sRzAoGAflQF"
            + System.lineSeparator()
            + "RHuRiG+/AngTPnZAhc0Zq0kwLkpH2Rid6IrFZhGLy8AUL/O6aa0IGoaMDLpSWUJp"
            + System.lineSeparator()
            + "nBY2S57MSM11/MVslrEgGmYNnI4r1K25xlaqV6K6ztEJv6n69327MS4NG8L/gCU5"
            + System.lineSeparator()
            + "3pEm38hkUi8pVYU7in7rx4TCkrq94OkzWJYurAkCgYATQCL/rJLQAlJIGulp8s6h"
            + System.lineSeparator()
            + "mQGwy8vIqMjAdHGLrCS35sVYBXG13knS52LJHvbVee39AbD5/LlWvjJGlQMzCLrw"
            + System.lineSeparator()
            + "F7oILW5kXxhb8S73GWcuMbuQMFVHFONbZAZgn+C9FW4l7XyRdkrbR1MRZ2km8YMs"
            + System.lineSeparator()
            + "/AHmo368d4PSNRMMzLHw8Q=="
            + System.lineSeparator()
            + "-----END PRIVATE KEY-----"
    ),
    NODE_CERT(
        "esnode.pem",
        "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "MIIEPDCCAySgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iIwDQYJKoZIhvcNAQEL"
            + System.lineSeparator()
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt"
            + System.lineSeparator()
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl"
            + System.lineSeparator()
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v"
            + System.lineSeparator()
            + "dCBDQTAeFw0yMzA4MjkwNDIzMTJaFw0zMzA4MjYwNDIzMTJaMFcxCzAJBgNVBAYT"
            + System.lineSeparator()
            + "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ0wCwYDVQQKDARub2RlMQ0wCwYDVQQLDARub2Rl"
            + System.lineSeparator()
            + "MRswGQYDVQQDDBJub2RlLTAuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA"
            + System.lineSeparator()
            + "A4IBDwAwggEKAoIBAQCm93kXteDQHMAvbUPNPW5pyRHKDD42XGWSgq0k1D29C/Ud"
            + System.lineSeparator()
            + "yL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0"
            + System.lineSeparator()
            + "HGkn47XVu3EwbfrTENg3jFu+Oem6a/501SzITzJWtS0cn2dIFOBimTVpT/4Zv5qr"
            + System.lineSeparator()
            + "XA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8n"
            + System.lineSeparator()
            + "dibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b6l+KLo3IKpfTbAIJXIO+M67FLtWKtttD"
            + System.lineSeparator()
            + "ao94B069skzKk6FPgW/OZh6PRCD0oxOavV+ld2SjAgMBAAGjgcYwgcMwRwYDVR0R"
            + System.lineSeparator()
            + "BEAwPogFKgMEBQWCEm5vZGUtMC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hxAAAAAA"
            + System.lineSeparator()
            + "AAAAAAAAAAAAAAABhwR/AAABMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEF"
            + System.lineSeparator()
            + "BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU0/qDQaY10jIo"
            + System.lineSeparator()
            + "wCjLUpz/HfQXyt8wHwYDVR0jBBgwFoAUF4ffoFrrZhKn1dD4uhJFPLcrAJwwDQYJ"
            + System.lineSeparator()
            + "KoZIhvcNAQELBQADggEBAD2hkndVih6TWxoe/oOW0i2Bq7ScNO/n7/yHWL04HJmR"
            + System.lineSeparator()
            + "MaHv/Xjc8zLFLgHuHaRvC02ikWIJyQf5xJt0Oqu2GVbqXH9PBGKuEP2kCsRRyU27"
            + System.lineSeparator()
            + "zTclAzfQhqmKBTYQ/3lJ3GhRQvXIdYTe+t4aq78TCawp1nSN+vdH/1geG6QjMn5N"
            + System.lineSeparator()
            + "1FU8tovDd4x8Ib/0dv8RJx+n9gytI8n/giIaDCEbfLLpe4EkV5e5UNpOnRgJjjuy"
            + System.lineSeparator()
            + "vtZutc81TQnzBtkS9XuulovDE0qI+jQrKkKu8xgGLhgH0zxnPkKtUg2I3Aq6zl1L"
            + System.lineSeparator()
            + "zYkEOUF8Y25J6WeY88Yfnc0iigI+Pnz5NK8R9GL7TYo="
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
    ),
    NODE_KEY(
        "esnode-key.pem",
        "-----BEGIN PRIVATE KEY-----"
            + System.lineSeparator()
            + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm93kXteDQHMAv"
            + System.lineSeparator()
            + "bUPNPW5pyRHKDD42XGWSgq0k1D29C/UdyL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0"
            + System.lineSeparator()
            + "o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0HGkn47XVu3EwbfrTENg3jFu+Oem6a/50"
            + System.lineSeparator()
            + "1SzITzJWtS0cn2dIFOBimTVpT/4Zv5qrXA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1"
            + System.lineSeparator()
            + "MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8ndibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b"
            + System.lineSeparator()
            + "6l+KLo3IKpfTbAIJXIO+M67FLtWKtttDao94B069skzKk6FPgW/OZh6PRCD0oxOa"
            + System.lineSeparator()
            + "vV+ld2SjAgMBAAECggEAQK1+uAOZeaSZggW2jQut+MaN4JHLi61RH2cFgU3COLgo"
            + System.lineSeparator()
            + "FIiNjFn8f2KKU3gpkt1It8PjlmprpYut4wHI7r6UQfuv7ZrmncRiPWHm9PB82+ZQ"
            + System.lineSeparator()
            + "5MXYqj4YUxoQJ62Cyz4sM6BobZDrjG6HHGTzuwiKvHHkbsEE9jQ4E5m7yfbVvM0O"
            + System.lineSeparator()
            + "zvwrSOM1tkZihKSTpR0j2+taji914tjBssbn12TMZQL5ItGnhR3luY8mEwT9MNkZ"
            + System.lineSeparator()
            + "xg0VcREoAH+pu9FE0vPUgLVzhJ3be7qZTTSRqv08bmW+y1plu80GbppePcgYhEow"
            + System.lineSeparator()
            + "dlW4l6XPJaHVSn1lSFHE6QAx6sqiAnBz0NoTPIaLyQKBgQDZqDOlhCRciMRicSXn"
            + System.lineSeparator()
            + "7yid9rhEmdMkySJHTVFOidFWwlBcp0fGxxn8UNSBcXdSy7GLlUtH41W9PWl8tp9U"
            + System.lineSeparator()
            + "hQiiXORxOJ7ZcB80uNKXF01hpPj2DpFPWyHFxpDkWiTAYpZl68rOlYujxZUjJIej"
            + System.lineSeparator()
            + "VvcykBC2BlEOG9uZv2kxcqLyJwKBgQDEYULTxaTuLIa17wU3nAhaainKB3vHxw9B"
            + System.lineSeparator()
            + "Ksy5p3ND43UNEKkQm7K/WENx0q47TA1mKD9i+BhaLod98mu0YZ+BCUNgWKcBHK8c"
            + System.lineSeparator()
            + "uXpauvM/pLhFLXZ2jvEJVpFY3J79FSRK8bwE9RgKfVKMMgEk4zOyZowS8WScOqiy"
            + System.lineSeparator()
            + "hnQn1vKTJQKBgElhYuAnl9a2qXcC7KOwRsJS3rcKIVxijzL4xzOyVShp5IwIPbOv"
            + System.lineSeparator()
            + "hnxBiBOH/JGmaNpFYBcBdvORE9JfA4KMQ2fx53agfzWRjoPI1/7mdUk5RFI4gRb/"
            + System.lineSeparator()
            + "A3jZRBoopgFSe6ArCbnyQxzYzToG48/Wzwp19ZxYrtUR4UyJct6f5n27AoGBAJDh"
            + System.lineSeparator()
            + "KIpQQDOvCdtjcbfrF4aM2DPCfaGPzENJriwxy6oEPzDaX8Bu/dqI5Ykt43i/zQrX"
            + System.lineSeparator()
            + "GpyLaHvv4+oZVTiI5UIvcVO9U8hQPyiz9f7F+fu0LHZs6f7hyhYXlbe3XFxeop3f"
            + System.lineSeparator()
            + "5dTKdWgXuTTRF2L9dABkA2deS9mutRKwezWBMQk5AoGBALPtX0FrT1zIosibmlud"
            + System.lineSeparator()
            + "tu49A/0KZu4PBjrFMYTSEWGNJez3Fb2VsJwylVl6HivwbP61FhlYfyksCzQQFU71"
            + System.lineSeparator()
            + "+x7Nmybp7PmpEBECr3deoZKQ/acNHn0iwb0It+YqV5+TquQebqgwK6WCLsMuiYKT"
            + System.lineSeparator()
            + "bg/ch9Rhxbq22yrVgWHh6epp"
            + System.lineSeparator()
            + "-----END PRIVATE KEY-----"
    ),
    ROOT_CA(
        "root-ca.pem",
        "-----BEGIN CERTIFICATE-----"
            + System.lineSeparator()
            + "MIIExjCCA66gAwIBAgIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcNAQEL"
            + System.lineSeparator()
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt"
            + System.lineSeparator()
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl"
            + System.lineSeparator()
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v"
            + System.lineSeparator()
            + "dCBDQTAeFw0yMzA4MjkwNDIwMDNaFw0yMzA5MjgwNDIwMDNaMIGPMRMwEQYKCZIm"
            + System.lineSeparator()
            + "iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ"
            + System.lineSeparator()
            + "RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290"
            + System.lineSeparator()
            + "IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwggEiMA0GCSqG"
            + System.lineSeparator()
            + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEPyN7J9VGPyJcQmCBl5TGwfSzvVdWwoQU"
            + System.lineSeparator()
            + "j9aEsdfFJ6pBCDQSsj8Lv4RqL0dZra7h7SpZLLX/YZcnjikrYC+rP5OwsI9xEE/4"
            + System.lineSeparator()
            + "U98CsTBPhIMgqFK6SzNE5494BsAk4cL72dOOc8tX19oDS/PvBULbNkthQ0aAF1dg"
            + System.lineSeparator()
            + "vbrHvu7hq7LisB5ZRGHVE1k/AbCs2PaaKkn2jCw/b+U0Ml9qPuuEgz2mAqJDGYoA"
            + System.lineSeparator()
            + "WSR4YXrOcrmPuRqbws464YZbJW898/0Pn/U300ed+4YHiNYLLJp51AMkR4YEw969"
            + System.lineSeparator()
            + "VRPbWIvLrd0PQBooC/eLrL6rvud/GpYhdQEUx8qcNCKd4bz3OaQ5AgMBAAGjggEW"
            + System.lineSeparator()
            + "MIIBEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU"
            + System.lineSeparator()
            + "F4ffoFrrZhKn1dD4uhJFPLcrAJwwgc8GA1UdIwSBxzCBxIAUF4ffoFrrZhKn1dD4"
            + System.lineSeparator()
            + "uhJFPLcrAJyhgZWkgZIwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ"
            + System.lineSeparator()
            + "k/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYD"
            + System.lineSeparator()
            + "VQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUg"
            + System.lineSeparator()
            + "Q29tIEluYy4gUm9vdCBDQYIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcN"
            + System.lineSeparator()
            + "AQELBQADggEBAIopqco/k9RSjouTeKP4z0EVUxdD4qnNh1GLSRqyAVe0aChyKF5f"
            + System.lineSeparator()
            + "qt1Bd1XCY8D16RgekkKGHDpJhGCpel+vtIoXPBxUaGQNYxmJCf5OzLMODlcrZk5i"
            + System.lineSeparator()
            + "jHIcv/FMeK02NBcz/WQ3mbWHVwXLhmwqa2zBsF4FmPCJAbFLchLhkAv1HJifHbnD"
            + System.lineSeparator()
            + "jQzlKyl5jxam/wtjWxSm0iyso0z2TgyzY+MESqjEqB1hZkCFzD1xtUOCxbXgtKae"
            + System.lineSeparator()
            + "dgfHVFuovr3fNLV3GvQk0s9okDwDUcqV7DSH61e5bUMfE84o3of8YA7+HUoPV5Du"
            + System.lineSeparator()
            + "8sTOKRf7ncGXdDRA8aofW268pTCuIu3+g/Y="
            + System.lineSeparator()
            + "-----END CERTIFICATE-----"
    );

    private final String fileName;
    private final String content;

    Certificates(String fileName, String content) {
        this.fileName = fileName;
        this.content = content;
    }

    public String getFileName() {
        return fileName;
    }

    public String getContent() {
        return content;
    }
}
