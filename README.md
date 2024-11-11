<div align="center">
<h1>Awesome Network Traffic Analysis </h1>
A curation of awesome papers, datasets and tools about network traffic analysis.
</div>

## Table of Contents
- [Papers](#papers)
    - [Survey](#survey)
    - [Network Traffic Classification](#network-traffic-classification)
        - [Offline: Pre-trained Models](#offline-pre-trained-models)
        - [Offline: DL/ML](#offline-dlml)
        - [Online: DL/ML](#online-dlml)
    - [Network Traffic Generation](#network-traffic-generation)
    - [Network Intrusion Detection](#network-intrusion-detection)
        - [Offline: DL/ML](#offline-dlml-1)
        - [Online: DL/ML](#online-dlml-1)
        - [Robustness](#robustness)
        - [Explainability](#explainability)
    - [Website Fingerprinting](#website-fingerprinting)

## Papers
### Survey
- SoK: A Critical Evaluation of Efficient Website Fingerprinting Defenses `S&P 2023` [[paper](https://ieeexplore.ieee.org/document/10179289)]
- SoK: Pragmatic Assessment of Machine Learning for Network Intrusion Detection, `EuroS&P 2023` [[paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10190520)] [[code](https://github.com/hihey54/pragmaticAssessment)]

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
#### Offline: DL/ML
- Trident: A Universal Framework for Fine-Grained and Class-Incremental Unknown Traffic Detection, `WWW 2024` [[paper](https://dl.acm.org/doi/10.1145/3589334.3645407)] [[code](https://github.com/Secbrain/Trident/)]
- ContraMTD: An Unsupervised Malicious Network Traffic Detection Method based on Contrastive Learning, `WWW 2024` [[paper](https://dl.acm.org/doi/10.1145/3589334.3645479)]
- Mateen: Adaptive Ensemble Learning for Network Anomaly Detection, `RAID 2024` [[paper](https://dl.acm.org/doi/10.1145/3678890.3678901)] [[code](https://github.com/ICL-ml4csec/Mateen/)]
- ReCDA: Concept Drift Adaptation with Representation Enhancement for Network Intrusion Detection, `KDD 2024` [[paper](https://dl.acm.org/doi/10.1145/3637528.3672007)]
- Proteus: A Difficulty-aware Deep Learning Framework for Real-time Malicious Traffic Detection, `ICNP 2024`
- SPIDER: A Semi-Supervised Continual Learning-based Network Intrusion Detection System, `Infocom 2024` [[paper](https://ieeexplore.ieee.org/document/10621428)]
- AOC-IDS: Autonomous Online Framework with Contrastive Learning for Intrusion Detection, `Infocom 2024` [[paper](https://arxiv.org/abs/2402.01807)] [[code](https://github.com/xinchen930/AOC-IDS)]
- Relative Frequency-Rank Encoding for Unsupervised Network Anomaly Detection, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10517994)]
- FOSS: Towards Fine-Grained Unknown Class Detection Against the Open-Set Attack Spectrum With Variable Legitimate Traffic, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10638516)]
- TMG-GAN: Generative Adversarial Networks-Based Imbalanced Learning for Network Intrusion Detection, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10312801)]
- RFG-HELAD: A Robust Fine-Grained Network Traffic Anomaly Detection Model Based on Heterogeneous Ensemble Learning, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10534080)]
- ProGen: Projection-Based Adversarial Attack Generation Against Network Intrusion Detection, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10531273)]
- Online Self-Supervised Deep Learning for Intrusion Detection Systems, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10531267)]
- K-GetNID: Knowledge-Guided Graphs for Early and Transferable Network Intrusion Detection, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10605850)]
- ECNet: Robust Malicious Network Traffic Detection With Multi-View Feature and Confidence Mechanism, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10592040)]
- ProGraph: Robust Network Traffic Identification With Graph Propagation, `ToN 2023` [[paper](https://ieeexplore.ieee.org/document/9933044)]
- Augmented Memory Replay-based Continual Learning Approaches for Network Intrusion Detection, `NeurIPS 2023` [[paper](https://proceedings.neurips.cc/paper_files/paper/2023/file/3755a02b1035fbadd5f93a022170e46f-Paper-Conference.pdf)]
- Point Cloud Analysis for ML-Based Malicious Traffic Detection: Reducing Majorities of False Positive Alarms, `CCS 2023` [[paper](https://dl.acm.org/doi/10.1145/3576915.3616631)]
- FARE: Enabling Fine-grained Attack Categorization under Low-quality Labeled Data, `NDSS 2021` [[paper](https://www.ndss-symposium.org/ndss-paper/fare-enabling-fine-grained-attack-categorization-under-low-quality-labeled-data/)]
- Throwing Darts in the Dark? Detecting Bots with Limited Data using Neural Data Augmentation, `S&P 2020` [[paper](https://ieeexplore.ieee.org/document/9152805)]

#### Online: DL/ML
- NetVigil: Robust and Low-Cost Anomaly Detection for East-West Data Center Security, `NSDI 2024` [[paper](https://www.usenix.org/system/files/nsdi24-hsieh.pdf)] [[code](https://github.com/microsoft/Yatesbury)]
- RIDS: Towards Advanced IDS via RNN Model and Programmable Switches Co-Designed Approaches, `Infocom 2024` [[paper](https://ieeexplore.ieee.org/document/10621290)] [[code](https://github.com/Secbrain/RIDS/)]
- Genos: General In-Network Unsupervised Intrusion Detection by Rule Extraction, `Infocom 2024` [[paper](https://arxiv.org/abs/2403.19248)]
- HorusEye: A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches, `Security 2023` [[paper](https://www.usenix.org/conference/usenixsecurity23/presentation/dong-yutao)] [[code](https://github.com/vicTorKd/HorusEye)]
- Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis, `NDSS 2023` [[paper](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/)] [[code](https://github.com/fuchuanpu/HyperVision)]
- Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection, `NDSS 2018` [[paper](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03A-3_Mirsky_paper.pdf)] [[code](https://github.com/ymirsky/KitNET-py)]

#### Robustness
- Low-Quality Training Data Only? A Robust Framework for Detecting Encrypted Malicious Network Traffic, `NDSS 2024` [[paper](https://www.ndss-symposium.org/wp-content/uploads/2024/10/ndss2024-81-slides.pdf)] [[code](https://github.com/XXnormal/RAPIER)]
- BARS: Local Robustness Certification for Deep Learning based Traffic Analysis Systems, `NDSS 2023` [[paper](https://www.ndss-symposium.org/ndss-paper/bars-local-robustness-certification-for-deep-learning-based-traffic-analysis-systems/)] [[code](https://github.com/KaiWangGitHub/BARS)]
- Anomaly Detection in the Open World: Normality Shift Detection, Explanation, and Adaptation, `NDSS 2023` [[paper](https://www.ndss-symposium.org/ndss-paper/anomaly-detection-in-the-open-world-normality-shift-detection-explanation-and-adaptation/)] [[code](https://github.com/dongtsi/OWAD)]
- CADE: Detecting and Explaining Concept Drift Samples for Security Applications, `Security 2021` [[paper](https://www.usenix.org/conference/usenixsecurity21/presentation/yang-limin)] [[code](https://github.com/whyisyoung/CADE)]


#### Explainability
- xNIDS: Explaining Deep Learning-based Network Intrusion Detection Systems for Active Intrusion Responses, `Security 2023` [[paper](https://www.usenix.org/conference/usenixsecurity23/presentation/wei-feng)] [[code](https://github.com/CactiLab/code-xNIDS)]
- Towards Understanding Alerts raised by Unsupervised Network
Intrusion Detection Systems, `RAID 2023` [[paper](https://dl.acm.org/doi/10.1145/3607199.3607247)]
- AI/ML for Network Security: The Emperor has no Clothes, `CCS 2022` [[paper](https://dl.acm.org/doi/10.1145/3548606.3560609)] [[code](https://github.com/TrusteeML/trustee)]


### Website Fingerprinting
TBD
