# 🚀 MiracleTool 2.0

![Backend Page](./img.png)

- **Latest MiracleTool tutorial**: https://www.youtube.com/watch?v=tKe9xUuFODA ***Must-see! Must-see! Must-see!!!***

- **Detailed explanation of Error 1101**: https://www.youtube.com/watch?v=r4uVTEJptdE

- Telegram discussion group: [@CMLiussss](https://t.me/CMLiussss)

## ⚠️ Disclaimer

This disclaimer applies to the "MiracleTool" project on GitHub (hereinafter referred to as "this project"), the project link is: https://github.com/iemabdullah/MiracleTool.

### Purpose This project is designed and developed solely for educational, research, and security testing purposes. It aims to provide security researchers, academics, and technology enthusiasts with a tool for exploring and practicing network communication technologies.

### Legality

When downloading and using this project code, users must comply with applicable laws and regulations. Users are responsible for ensuring their actions comply with the legal framework, regulations, and other relevant provisions of their region.

### Disclaimer

1. As the **author of secondary development** of this project (hereinafter referred to as the "Author"), I, **cmliu**, emphasize that this project is intended solely for legal, ethical, and educational purposes.

2. The Author does not endorse, support, or encourage any form of illegal use. The Author strongly condemns any use of this project for any illegal or unethical activities.

3. The Author assumes no responsibility for any illegal activities undertaken by any person or organization using this project code. Users are solely responsible for any consequences arising from the use of this project code.

4. The Author is not liable for any direct or indirect damages that may arise from the use of this project code.

5. To avoid any unforeseen consequences or legal risks, users should delete the code within 24 hours of use.

By using this project code, users acknowledge and agree to all terms of this disclaimer. If you do not agree to these terms, you should immediately stop using this project.

The author reserves the right to update this disclaimer at any time without notice. The latest version of the disclaimer will be published on the project's GitHub page.

## 🔥 Risk Warning

- Avoid node configuration information leakage by submitting fake node configurations to the subscription service.

- Alternatively, you can choose to deploy the [WorkerVless2sub subscription generation service](https://github.com/cmliu/WorkerVless2sub) yourself, which allows you to take advantage of the convenience of the subscription generator.

## 💡 How to Use?

### ⚙️ Workers Deployment Method [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=191s)

<details>

<summary><code><strong>“Workers Deployment Text Tutorial”</strong></code></summary>

1. Deploying CF Workers:

- Create a new Worker in the CF Worker console.

- Paste the contents of [worker.js](https://github.com/iemabdullah/MiracleTool/blob/main/_worker.js) into the Worker editor.

- In the `Settings` tab on the left, select `Variables` > `Add Variable`.

Enter **ADMIN** as the variable name and your administrator password as the value, then click `Save`.

2. Bind a Key-Value Namespace:

- In the `Bindings` tab, select `Add Binding +` > `Key-Value Namespace` > `Add Binding`, then select an existing namespace or create a new one to bind.

- Enter **KV** as the `Variable Name`, then click `Add Binding`.

3. Bind a Custom Domain to Workers:

- In the Workers console, in the `Triggers` tab, click `Add Custom Domain`.

- Enter your subdomain that you have transferred to the CF DNS service, for example: `vless.google.com`, then click `Add Custom Domain` and wait for the certificate to take effect.

- **If you are a beginner, you can jump right in now and don't need to read any further!!!**

4. Access the Backend:

- Visit `https://vless.google.com/admin` and enter the administrator password to log in to the backend.

</details>

### 🛠 Pages Upload and Deployment Method **Best Recommendation!!!** [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=436s)

<details>
<summary><code><strong>“Pages File Upload and Deployment Text Tutorial”</strong></code></summary>

1. Deploying CF Pages:

- Download the [main.zip](https://github.com/iemabdullah/MiracleTool//archive/refs/heads/main.zip) file and star it!!!

- In the CF Pages console, select `Upload Assets`, name your project, click `Create Project`, then upload the downloaded [main.zip](https://github.com/iemabdullah/MiracleTool/archive/refs/heads/main.zip) file and click `Deploy Site`.

- After deployment, click `Continue Processing Site`, then select `Settings` > `Environment Variables` > **Create** a variable for the production environment > `Add Variable`.

Enter `ADMIN` as the variable name and your administrator password as the value, then click `Save`.

- Return to the `Deployment` tab, click `Create New Deployment` in the lower right corner, then re-upload the `[main.zip](https://github.com/iemabdullah/MiracleTool/archive/refs/heads/main.zip)` file and click `Save and Deploy`.

2. Binding a KV Namespace:

- In the `Settings` tab, select `Binding` > `+ Add` > `KV Namespace`, then select an existing namespace or create a new one to bind.

- Enter `KV` as the `Variable Name`, then click `Save` and retry the deployment.

3. Bind a custom CNAME record to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)

- In the Pages console, on the `Custom Domain` tab, click `Set Up Custom Domain`.

- Enter your custom subdomain. Do not use your root domain. For example:

If your assigned domain is `fuck.cloudns.biz`, then add a custom domain by entering `lizi.fuck.cloudns.biz`.

- As required by Cloudflare, your domain's DNS provider will be returned. Add the CNAME record `MiracleTool` for the custom domain `lizi`, then click `Activate Domain`.

- **If you are a beginner, you can immediately start using your Pages domain after binding a custom domain; you don't need to read further!** **

4. Accessing the Backend:

- Visit `https://lizi.fuck.cloudns.biz/admin` and enter the administrator password to log in to the backend.

</details>

### 🛠 Pages GitHub Deployment Method [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=317s)

<details>

<summary><code><strong>「Pages GitHub Deployment Text Tutorial」</strong></code></summary>

1. Deploying CF Pages:

- Fork this project on GitHub and star it!!!

- In the CF Pages console, select `Connect to Git`, select the `MiracleTool` project, and click `Start Setup`.

1. **Set up build and deployment** On the Pages panel, select Environment Variables (Advanced) and then Add a variable.

Name the variable with **ADMIN** and set the value to your administrator password. Then click Save and Deploy.

2. **Bind KV Namespace**:

In the Settings tab, select Bindings > Add > KV Namespace. Choose an existing namespace or create a new one to bind.

Name the variable with **KV** and click Save. Then try deploying again.

3. **Bind a custom CNAME domain to Pages:** [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)

In the Pages console, on the Custom Domains tab, click Set up a custom domain.

- Enter your custom subdomain. Do not use your root domain. For example:

If your assigned domain is `fuck.cloudns.biz`, then add a custom domain by entering `lizi.fuck.cloudns.biz`.

- As required by Cloudn Provider (CF), your domain's DNS service provider will be returned. Add the CNAME record `MiracleTool` for the custom domain `lizi`, then click `Activate Domain`.

- **If you are a beginner, you can start using your Pages application immediately after binding your custom domain; you don't need to read further!**

4. Accessing the Backend:

- Visit `https://lizi.fuck.cloudns.biz/admin` and enter the administrator password to log in to the backend.

</details>

## 🔑 Variable Description

| Variable Name | Example | Required | Remarks |

|--------|---------|-|-----|

| ADMIN | `123456` |✅| Panel Login Password |

| KEY | `token` |❌| Quick subscription key, access `/token` to quickly subscribe. | | UUID | `90cd4a77-141a-43c9-991b-08263cfe9c10` |❌| Force use of a fixed UUID |

| PROXYIP | `proxyip.cmliussss.net:443` |❌| Change the default built-in PROXYIP |

| URL | `https://blog.cmliussss.com` |❌| Homepage reverse proxy spoofing (random settings easily trigger anti-fraud measures; reverse proxying blocked websites will accelerate the domain's blocking) |

| GO2SOCKS5 | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` |❌| After setting the `SOCKS5` or `HTTP` variable, you can set a list of websites that force the use of SOCKS5 access (setting it to `*` can act as a global proxy) |

## 🔧 Practical Tips: The nodes deployed in this project can use specified `PROXYIP` or `SOCKS5` via the node's PATH (path)! **

- Specify `PROXYIP` Example

``url

/proxyip=proxyip.cmliussss.net

/?proxyip=proxyip.cmliussss.net

/proxyip.cmliussss.net (Only applicable to domains starting with 'proxyip.')

```

- Specify `SOCKS5` Example

``url

/socks5=user:password@127.0.0.1:1080

/?socks5=user:password@127.0.0.1:1080

/socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (Global SOCKS5 activated by default)

/socks5://user:password@127.0.0.1:1080 (Global SOCKS5 activated by default) ```

- Specify `HTTP Proxy` Example

```url

/http=user:password@127.0.0.1:1080

/http://user:password@127.0.0.1:8080 (Default global SOCKS5 activation)

```

## ⭐ Star Give It a Star!

[![Stargazers over time](https://starchart.cc/cmliu/edgetunnel.svg?variant=adaptive)](https://starchart.cc/cmliu/edgetunnel)

## 💻 Client Compatible

### Windows

- [v2rayN](https://github.com/2dust/v2rayN)

- clash.meta([FlClash](https://github.com/chen08209/FlClash),[mihomo-party](https://github.com/mihomo-party-org/mihomo-party),[clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev),[Clash Nyanpasu](https://github.com/keiko233/clash-nyanpasu)）
### IOS 
- Surge, little rocket 
- sing-box（[SFI](https://sing-box.sagernet.org/zh/clients/apple/)）
### Android 
- clash.meta ([ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid), [FlClash](https://github.com/chen08209/FlClash)) 
- sing-box ([SFA](https://github.com/SagerNet/sing-box))

### MacOS

- clash.meta ([FlClash](https://github.com/chen08209/FlClash), [mihomo-party](https://github.com/mihomo-party-org/mihomo-party))

# 🙏 Special Thanks

### 💖 Sponsorship Support - Providing cloud servers to maintain [Subscription Conversion Service](https://sub.cmliussss.net/)

- [NodeLoc](https://www.nodeloc.com/)

- [Alice](https://url.cmliussss.com/alice)

- [EasyLinks](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)
