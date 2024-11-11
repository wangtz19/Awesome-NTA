<div align="center">
<h1>Awesome Network Traffic Analysis </h1>
A curation of awesome papers, datasets and tools about network traffic analysis.
</div>

## Table of Contents
TBD

## Papers
### Survey
- SoK: A Critical Evaluation of Efficient Website Fingerprinting Defenses `S&P 2023` [[paper](https://ieeexplore.ieee.org/document/10179289)]
- SoK: Pragmatic Assessment of Machine Learning for Network Intrusion Detection, `EuroS&P 2923` [[paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10190520)] [[code](https://github.com/hihey54/pragmaticAssessment)]

### Network Traffic Classification
#### Offline: Pre-trained Models
- TrafficFormer: An Efficient Pre-trained Model for Traffic Data, `S&P 2025` [[paper](http://www.thucsnet.com/wp-content/papers/guangmeng_sp2025.pdf)] [[code](https://github.com/kojunseo/Trafficformer)]
- NetMamba: Efficient Network Traffic Classification via Pre-training Unidirectional Mamba, `ICNP 2024` [[paper](https://arxiv.org/abs/2405.11449)] [[code](https://github.com/wangtz19/NetMamba)]
- PTU: Pre-trained Model for Network Traffic Understanding, `ICNP 2024`
- TrafficGPT: Breaking the Token Barrier for Efficient Long Traffic Analysis and Generation, `arxiv 2024` [[paper](https://arxiv.org/pdf/2403.05822)]
- Lens: A Foundation Model for Network Traffic in Cybersecurity, `arxiv 2024` [[paper](https://arxiv.org/abs/2402.03646)]
- Flow-MAE: Leveraging Masked AutoEncoder for Accurate, Efficient and Robust Malicious Traffic Classification, `RAID 2023` [[paper](https://dl.acm.org/doi/10.1145/3607199.3607206)] [[code](https://github.com/NLear/Flow-MAE)]
- Yet Another Traffc Classifer: A Masked Autoencoder Based Traffc Transformer with Multi-Level Flow Representation, `AAAI 2023` [[paper](https://dl.acm.org/doi/10.1609/aaai.v37i4.25674)] [[code](https://github.com/NSSL-SJTU/YaTC)]
- ET-BERT: A Contextualized Datagram Representation with Pre-training Transformers for Encrypted Traffic Classification, `WWW 2022` [[paper](https://dl.acm.org/doi/10.1145/3485447.3512217)][[code](https://github.com/linwhitehat/ET-BERT)]
- PERT: Payload Encoding Representation from Transformer for Encrypted Traffic Classification, `ITU 2020` [[paper](https://ieeexplore.ieee.org/document/9303204)]

#### Offline: DL/ML
- TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks for Fine-grained Encrypted Trafic Classification, `WWW 2023` [[paper](https://dl.acm.org/doi/10.1145/3543507.3583227)] [[code](https://github.com/ViktorAxelsen/TFE-GNN)]
- AppSniffer: Towards Robust Mobile App Fingerprinting Against VPN, `WWW 2023` [[paper](https://dl.acm.org/doi/10.1145/3543507.3583473)] [[code](https://github.com/network-traffic/AppSniffer)]
- Rosetta: Enabling Robust TLS Encrypted Traffic Classification in Diverse Network Environments with TCP-Aware Traffic Augmentation，`Security 2023` [[paper](https://www.usenix.org/system/files/usenixsecurity23-xie.pdf)] [[code](https://github.com/sunskyXX/Rosetta)]
- Encrypted Malware Traffic Detection via Graph-based Network Analysis, `RAID 2022` [[paper](https://dl.acm.org/doi/10.1145/3545948.3545983)]
- Packet Representation Learning for Traffic Classification, `KDD 2022` [[paper](https://dl.acm.org/doi/10.1145/3534678.3539085)] [[code](https://github.com/ict-net/PacRep)]
- MT-FlowFormer: A Semi-Supervised Flow Transformer for Encrypted Traffic Classification, `KDD 2022` [[paper](https://dl.acm.org/doi/10.1145/3534678.3539314)]
- Accurate Decentralized Application Identification via Encrypted Traffic Analysis Using Graph Neural Networks, `TIFS 2021` [[paper](https://ieeexplore.ieee.org/document/9319399)]
- FlowPrint: Semi-Supervised Mobile-App Fingerprinting on Encrypted Network Traffic, `NDSS 2020` [[paper](https://www.ndss-symposium.org/ndss-paper/flowprint-semi-supervised-mobile-app-fingerprinting-on-encrypted-network-traffic/)] [[code](https://github.com/Thijsvanede/FlowPrint)]
- FS-Net: A Flow Sequence Network For Encrypted Traffic Classification, `Infocom 2019` [[paper](https://ieeexplore.ieee.org/document/8737507)] [[code](https://github.com/WSPTTH/FS-Net)]
- Robust Smartphone App Identification via Encrypted Network Traffic Analysis, `TIFS 2018` [[paper](https://ieeexplore.ieee.org/document/8006282)] [[code](https://github.com/vftaylor/appscanner)]

#### Online: DL/ML
- Leo: Online ML-based Traffic Classification at Multi-Terabit Line Rate, `NSDI 2024` [[paper](https://www.usenix.org/conference/nsdi24/presentation/jafri)] [[code](https://github.com/Purdue-ISL/Leo)]
- Brain-on-Switch: Towards Advanced Intelligent Network Data Plane via NN-Driven Traffic Analysis at Line-Speed, `NSDI 2024` [[paper](https://www.usenix.org/conference/nsdi24/presentation/yan)] [[code](https://github.com/InspiringGroup-Lab/Brain-on-Switch)]
- LINC: Enabling Low-Resource In-network Classification and Incremental Model Update, `ICNP 2024`
- IIsy: Hybrid In-Network Classification Using Programmable Switches, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10439067)] [[code](https://github.com/In-Network-Machine-Learning/IIsy)]
- Recursive Multi-Tree Construction With Efficient Rule Sifting for Packet Classification on FPGA, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10315073)] [[code](https://github.com/wenjunpaper/KickTree)]

### Network Traffic Generation
- NetDiffusion: Network Data Augmentation Through Protocol-Constrained Traffic Generation, `SIGMETRICS 2023`[[paper](https://dl.acm.org/doi/10.1145/3639037)] [[code](https://github.com/noise-lab/NetDiffusion_Generator)]
- Datacenter Network Deserves Be!er Traffic Models, `Hotnets 2023` [[paper](https://conferences.sigcomm.org/hotnets/2023/papers/hotnets23_huang.pdf)]
- Practical GAN-based synthetic IP header trace generation using NetShare, `SIGCOMM 2022` [[paper](https://dl.acm.org/doi/10.1145/3544216.3544251)] [[code](https://github.com/netsharecmu/NetShare)]
- Locality Matters! Traffic Demand Modeling in Datacenter Networks, `APNET 2022` [[paper](https://conferences.sigcomm.org/events/apnet2022/papers/Locality%20Matters!%20Traffic%20Demand%20Modeling%20in%20Datacenter%20Networks.pdf)]

### Network Intrusion Detection
TBD

### Website Fingerprinting
TBD
