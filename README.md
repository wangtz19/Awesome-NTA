<div align="center">
<img src=".assets/awesome-nta-banner.png" alt="Awesome Network Traffic Analysis" width="100%">
<h1>Awesome Network Traffic Analysis </h1>
A curation of awesome papers, datasets and tools about network traffic analysis.
</div>

## Table of Contents
- [Papers](#papers)
    - [Survey](#survey)
    - [Network Traffic Classification](#network-traffic-classification)
        - [Offline: Pre-trained Models](#offline-pre-trained-models)
        - [Offline: DL/ML](#offline-dlml)
        - [Online: DL/ML (In-Network)](#online-dlml-in-network)
    - [Network Traffic Generation](#network-traffic-generation)
    - [Network Intrusion Detection](#network-intrusion-detection)
        - [Offline: DL/ML](#offline-dlml-1)
        - [Online: DL/ML (In-Network)](#online-dlml-in-network-1)
    - [Robustness](#robustness)
    - [Explainability](#explainability)
    - [Website Fingerprinting](#website-fingerprinting)
    - [Mobile App Fingerprinting](#mobile-app-fingerprinting)
    - [APT Detection & Provenance Graph IDS](#apt-detection--provenance-graph-ids)
    - [Traffic Analysis under Distribution Shift](#traffic-analysis-under-distribution-shift)
    - [Datasets & Benchmarks](#datasets--benchmarks)
- [Datasets](#datasets)
    - [Encrypted Traffic & Anonymity](#encrypted-traffic--anonymity)
    - [Intrusion Detection & Attacks](#intrusion-detection--attacks)
        - [DDoS](#ddos)
        - [DNS / DoH Tunneling](#dns--doh-tunneling)
        - [Botnet](#botnet)
        - [IDS / IoT](#ids--iot)
    - [Application & Mobile-App Identification](#application--mobile-app-identification)
    - [Concept Drift](#concept-drift)
    - [Malware Traffic](#malware-traffic)
- [Tools](#tools)
    - [Packet Parsing](#packet-parsing)
    - [Packet Splitting / Editing](#packet-splitting--editing)
    - [Flow Feature Extraction](#flow-feature-extraction)
    - [Traffic Replay / Generation](#traffic-replay--generation)
    - [Anonymization](#anonymization)
- [License](#license)

## Papers
### Survey
- A Comprehensive Survey on Network Traffic Synthesis From Statistical Models to Deep Learning, `arxiv 2025` [[paper](http://arxiv.org/abs/2507.01976)]
- Introducing a Comprehensive, Continuous, and Collaborative Survey of Intrusion Detection Datasets, `CSET 2024` [[paper](https://doi.org/10.1145/3675741.3675754)]
- A Survey of Public IoT Datasets for Network Security Research, `CST 2023` [[paper](https://doi.org/10.1109/COMST.2023.3288942)]
- SoK: A Critical Evaluation of Efficient Website Fingerprinting Defenses, `S&P 2023` [[paper](https://doi.org/10.1109/SP46215.2023.10179289)]
- SoK: Pragmatic Assessment of Machine Learning for Network Intrusion Detection, `EuroS&P 2023` [[paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10190520)] [[code](https://github.com/hihey54/pragmaticAssessment)]
- Dos and Don&apos;ts of Machine Learning in Computer Security, `Security 2022` [[paper](https://www.usenix.org/conference/usenixsecurity22/presentation/arp)]
### Network Traffic Classification
#### Offline: Pre-trained Models
- Convolutions are Competitive with Transformers for Encrypted Traffic Classification with Pre-training, `arxiv 2025` [[paper](https://arxiv.org/abs/2508.02001)]
- Demystifying Network Foundation Models, `NeurIPS 2025` [[paper](https://arxiv.org/abs/2509.23089)]
- FlowletFormer: Network Behavioral Semantic Aware Pre-training Model for Traffic Classification, `arxiv 2025` [[paper](https://arxiv.org/abs/2508.19924)]
- MM4flow: A Pre-trained Multi-modal Model for Versatile Network Traffic Analysis, `CCS 2025` [[paper](https://doi.org/10.1145/3719027.3744804)]
- TrafficFormer: An Efficient Pre-trained Model for Traffic Data, `S&P 2025` [[paper](http://www.thucsnet.com/wp-content/papers/guangmeng_sp2025.pdf)] [[code](https://github.com/kojunseo/Trafficformer)]
- netFound: Foundation Model for Network Security, `arxiv 2025` [[paper](https://arxiv.org/abs/2310.17025)]
- A Novel Self-Supervised Framework Based on Masked Autoencoder for Traffic Classification, `ToN 2024` [[paper](https://doi.org/10.1109/tnet.2023.3335253)]
- Lens: A Foundation Model for Network Traffic in Cybersecurity, `arxiv 2024` [[paper](https://arxiv.org/abs/2402.03646)]
- NetBench: A Large-Scale and Comprehensive Network Traffic Benchmark Dataset for Foundation Models, `arxiv 2024` [[paper](https://arxiv.org/abs/2403.10319)]
- NetMamba: Efficient Network Traffic Classification via Pre-training Unidirectional Mamba, `ICNP 2024` [[paper](https://arxiv.org/abs/2405.11449)] [[code](https://github.com/wangtz19/NetMamba)]
- PTU: Pre-trained Model for Network Traffic Understanding, `ICNP 2024`
- TrafficGPT: Breaking the Token Barrier for Efficient Long Traffic Analysis and Generation, `arxiv 2024` [[paper](https://arxiv.org/pdf/2403.05822)] [[code](https://github.com/lijlansg/TrafficGPT)]
- Flow-MAE: Leveraging Masked AutoEncoder for Accurate, Efficient and Robust Malicious Traffic Classification, `RAID 2023` [[paper](https://dl.acm.org/doi/10.1145/3607199.3607206)] [[code](https://github.com/NLear/Flow-MAE)]
- Listen to Minority: Encrypted Traffic Classification for Class Imbalance with Contrastive Pre-Training, `SECON 2023` [[paper](https://doi.org/10.1109/SECON58729.2023.10287449)]
- NetGPT: Generative Pretrained Transformer for Network Traffic, `arxiv 2023` [[paper](https://arxiv.org/pdf/2304.09513)] [[code](https://github.com/ict-net/NetGPT)]
- Yet Another Traffic Classifier: A Masked Autoencoder Based Traffic Transformer with Multi-Level Flow Representation, `AAAI 2023` [[paper](https://dl.acm.org/doi/10.1609/aaai.v37i4.25674)] [[code](https://github.com/NSSL-SJTU/YaTC)]
- ET-BERT: A Contextualized Datagram Representation with Pre-training Transformers for Encrypted Traffic Classification, `WWW 2022` [[paper](https://dl.acm.org/doi/10.1145/3485447.3512217)] [[code](https://github.com/linwhitehat/ET-BERT)]
- Pert: Payload Encoding Representation from Transformer for Encrypted Traffic Classification, `ITU 2020` [[paper](https://ieeexplore.ieee.org/document/9303204)]
#### Offline: DL/ML
- Pacc: Protocol-Aware Cross-Layer Compression for Compact Network Traffic Representation, `arxiv 2026` [[paper](https://arxiv.org/abs/2602.08331)]
- Synecdoche: Efficient and Accurate In-Network Traffic Classification via Direct Packet Sequential Pattern Matching, `arxiv 2026` [[paper](https://arxiv.org/abs/2512.21116)]
- Cato: End-to-End Optimization of ML-Based Traffic Analysis Pipelines, `S&P 2025` [[paper](https://arxiv.org/abs/2402.06099)]
- FastFlow: Early Yet Robust Network Flow Classification using the Minimal Number of Time-Series Packets, `sigmetrics 2025` [[paper](https://doi.org/10.1145/3727115)] [[code](https://github.com/mayfly227/fastflow)]
- Less is More: Simplifying Network Traffic Classification Leveraging RFCs, `arxiv 2025` [[paper](https://doi.org/10.1145/3701716.3715492)]
- Miett: Multi-Instance Encrypted Traffic Transformer for Encrypted Traffic Classification, `AAAI 2025` [[paper](https://doi.org/10.1609/aaai.v39i15.33748)]
- Multi-view Correlation-aware Network Traffic Detection on Flow Hypergraph, `arxiv 2025` [[paper](https://arxiv.org/abs/2501.08610)]
- One task to rule them all: A closer look at traffic classification generalizability, `arxiv 2025` [[paper](https://arxiv.org/abs/2507.06430)]
- Revolutionizing Encrypted Traffic Classification with MH-Net: A Multi-View Heterogeneous Graph Model, `AAAI 2025` [[paper](https://doi.org/10.1609/aaai.v39i1.32091)]
- SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers, `S&P 2025` [[paper](https://doi.org/10.1109/SP61157.2025.00165)]
- The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification, `sigcomm 2025` [[paper](https://doi.org/10.1145/3718958.3750498)]
- TrafficLLM: Enhancing Large Language Models for Network Traffic Analysis with Generic Traffic Representation, `arxiv 2025` [[paper](https://arxiv.org/abs/2504.04222)] [[code](https://github.com/ZGC-LLM-Safety/TrafficLLM)]
- When Simple Model Just Works: Is Network Traffic Classification in Crisis?, `arxiv 2025` [[paper](https://arxiv.org/abs/2506.08655)]
- Fingerprinting the Shadows: Unmasking Malicious Servers with Machine Learning-Powered TLS Analysis, `WWW 2024` [[paper](https://doi.org/10.1145/3589334.3645719)]
- Identifying VPN Servers through Graph-Represented Behaviors, `WWW 2024` [[paper](https://doi.org/10.1145/3589334.3645552)]
- Mpaf: Encrypted Traffic Classification With Multi-Phase Attribute Fingerprint, `TIFS 2024` [[paper](https://doi.org/10.1109/TIFS.2024.3428839)]
- ServeFlow: A Fast-Slow Model Architecture for Network Traffic Analysis, `arxiv 2024` [[paper](https://arxiv.org/abs/2402.03694)]
- Understanding Web Fingerprinting with a Protocol-Centric Approach, `RAID 2024` [[paper](https://doi.org/10.1145/3678890.3678910)]
- Classify Traffic Rather Than Flow: Versatile Multi-Flow Encrypted Traffic Classification With Flow Clustering, `TNSM 2023` [[paper](https://doi.org/10.1109/TNSM.2023.3322861)]
- GGFAST: Automating Generation of Flexible Network Traffic Classifiers, `Sigcomm 2023` [[paper](https://doi.org/10.1145/3603269.3604840)]
- ProGraph: Robust Network Traffic Identification With Graph Propagation, `ToN 2023` [[paper](https://ieeexplore.ieee.org/document/9933044)]
- Replication: Contrastive Learning and Data Augmentation in Traffic Classification Using a Flowpic Input Representation, `IMC 2023` [[paper](https://doi.org/10.1145/3618257.3624820)]
- Revolutionizing Cyber Threat Detection with Large Language Models, `arxiv 2023` [[paper](https://arxiv.org/abs/2306.14263)]
- TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks for Fine-grained Encrypted Traffic Classification, `WWW 2023` [[paper](https://dl.acm.org/doi/10.1145/3543507.3583227)] [[code](https://github.com/ViktorAxelsen/TFE-GNN)]
- A few shots traffic classification with mini-FlowPic augmentations, `IMC 2022` [[paper](https://doi.org/10.1145/3517745.3561436)] [[code](https://github.com/eyalho/mini-flowpic-traffic-classification)]
- MT-FlowFormer: A Semi-Supervised Flow Transformer for Encrypted Traffic Classification, `KDD 2022` [[paper](https://dl.acm.org/doi/10.1145/3534678.3539314)]
- MTT: an efficient model for encrypted network traffic classification using multi-task transformer, `springer 2022` [[paper](https://doi.org/10.1007/s10489-021-03032-8)]
- Packet Representation Learning for Traffic Classification, `KDD 2022` [[paper](https://dl.acm.org/doi/10.1145/3534678.3539085)] [[code](https://github.com/ict-net/PacRep)]
- Seeing Traffic Paths: Encrypted Traffic Classification With Path Signature Features, `TIFS 2022` [[paper](https://doi.org/10.1109/TIFS.2022.3179955)]
- Accurate Decentralized Application Identification via Encrypted Traffic Analysis Using Graph Neural Networks, `TIFS 2021` [[paper](https://ieeexplore.ieee.org/document/9319399)]
- New Directions in Automated Traffic Analysis, `CCS 2021` [[paper](https://doi.org/10.1145/3460120.3484758)]
- TSCRNN: A novel classification scheme of encrypted traffic based on flow spatiotemporal features for efficient management of IIoT, `ComNet 2021` [[paper](https://doi.org/10.1016/j.comnet.2021.107974)]
- Deep packet: a novel approach for encrypted traffic classification using deep learning, `SoftComputing 2020` [[paper](https://doi.org/10.1007/s00500-019-04030-2)]
- FS-Net: A Flow Sequence Network For Encrypted Traffic Classification, `Infocom 2019` [[paper](https://ieeexplore.ieee.org/document/8737507)] [[code](https://github.com/WSPTTH/FS-Net)]
- FlowPic: Encrypted Internet Traffic Classification is as Easy as Image Recognition, `Infocom workshop 2019` [[paper](https://doi.org/10.1109/INFCOMW.2019.8845315)] [[code](https://github.com/talshapira/FlowPic)]
- Seq2Img: A sequence-to-image based approach towards IP traffic classification using convolutional neural networks, `BigData 2017` [[paper](https://doi.org/10.1109/BigData.2017.8258054)]
- A preliminary performance comparison of five machine learning algorithms for practical IP traffic flow classification, `sigmetrics 2006` [[paper](https://doi.org/10.1145/1163593.1163596)]
- BLINC: Multilevel Traffic Classification in the Dark, `sigcomm 2005` [[paper](https://dl.acm.org/doi/10.1145/1080091.1080119)]
- Internet traffic classification using bayesian analysis techniques, `sigmetrics 2005` [[paper](https://doi.org/10.1145/1064212.1064220)]
#### Online: DL/ML (In-Network)
- Brain-on-Switch: Towards Advanced Intelligent Network Data Plane via NN-Driven Traffic Analysis at Line-Speed, `NSDI 2024` [[paper](https://www.usenix.org/conference/nsdi24/presentation/yan)] [[code](https://github.com/InspiringGroup-Lab/Brain-on-Switch)]
- Caravan: Practical Online Learning of In-Network ML Models with Labeling Agents, `OSDI 2024` [[paper](https://www.usenix.org/conference/osdi24/presentation/zhou-qizheng)]
- High-Throughput Stateless-But-Complex Packet Processing Within a Tbps Programmable Switch, `ICNP 2024` [[paper](https://doi.org/10.1109/ICNP61940.2024.10858513)]
- IIsy: Hybrid In-Network Classification Using Programmable Switches, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10439067)] [[code](https://github.com/In-Network-Machine-Learning/IIsy)]
- Linc: Enabling Low-Resource in-Network Classification and Incremental Model Update, `ICNP 2024` [[paper](https://doi.org/10.1109/ICNP61940.2024.10858585)] [[code](https://github.com/haolinyan/LINC)]
- Leo: Online ML-based Traffic Classification at Multi-Terabit Line Rate, `NSDI 2024` [[paper](https://www.usenix.org/conference/nsdi24/presentation/jafri)] [[code](https://github.com/Purdue-ISL/Leo)]
- Recursive Multi-Tree Construction With Efficient Rule Sifting for Packet Classification on FPGA, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10315073)] [[code](https://github.com/wenjunpaper/KickTree)]
### Network Traffic Generation
- DiffuPac: Contextual Mimicry in Adversarial Packets Generation via Diffusion Model, `NeurIPS 2024` [[paper](https://dl.acm.org/doi/10.5555/3737916.3742169)]
- Diffusion Model-based Mobile Traffic Generation with Open Data for Network Planning and Optimization, `KDD 2024` [[paper](https://doi.org/10.1145/3637528.3671544)]
- Feasibility of State Space Models for Network Traffic Generation, `NAIC 2024` [[paper](https://doi.org/10.1145/3672198.3673792)]
- NetDiff: A Service-Guided Hierarchical Diffusion Model for Network Flow Trace Generation, `CoNext3 2024` [[paper](https://doi.org/10.1145/3676870)]
- Synthetic and privacy-preserving traffic trace generation using generative ai models for training network intrusion detection systems, `elsevier 2024` [[paper](https://www.sciencedirect.com/science/article/pii/S1084804524001036)] [[code](https://codeberg.org/CiroGuida/GenAI-network-traffic)]
- Datacenter Network Deserves Better Traffic Models, `Hotnets 2023` [[paper](https://conferences.sigcomm.org/hotnets/2023/papers/hotnets23_huang.pdf)]
- NetDiffus: Network Traffic Generation by Diffusion Models through Time-Series Imaging, `arxiv 2023` [[paper](https://arxiv.org/pdf/2310.04429)] [[code](https://github.com/Nirhoshan/NetDiffus?tab=readme-ov-file)]
- NetDiffusion: Network Data Augmentation Through Protocol-Constrained Traffic Generation, `SIGMETRICS 2023` [[paper](https://dl.acm.org/doi/10.1145/3639037)] [[code](https://github.com/noise-lab/NetDiffusion_Generator)]
- PAC-GPT: A novel approach to generating synthetic network traffic with GPT-3, `arxiv 2023` [[paper](https://ieeexplore.ieee.org/document/10287342)] [[code](https://github.com/dark-0ne/NetworkPacketGenerator)]
- Locality Matters! Traffic Demand Modeling in Datacenter Networks, `APNET 2022` [[paper](https://conferences.sigcomm.org/events/apnet2022/papers/Locality%20Matters!%20Traffic%20Demand%20Modeling%20in%20Datacenter%20Networks.pdf)]
- Necstgen: An approach for realistic network traffic generation using deep learning, `GLOBECOM 2022` [[paper](https://ieeexplore.ieee.org/document/10000731)] [[code](https://github.com/fmeslet/NeCSTGen)]
- Practical GAN-based synthetic IP header trace generation using NetShare, `SIGCOMM 2022` [[paper](https://dl.acm.org/doi/10.1145/3544216.3544251)] [[code](https://github.com/netsharecmu/NetShare)]
- Stan: Synthetic Network Trafic Generation with Generative Neural Models, `arxiv 2021` [[paper](https://arxiv.org/pdf/2009.12740)] [[code](https://github.com/ShengzheXu/stan.git)]
- Using GANs for Sharing Networked Time Series Data: Challenges, Initial Promise, and Open Questions, `IMC 2020` [[paper](https://arxiv.org/pdf/1909.13403)] [[code](https://github.com/fjxmlzn/DoppelGANger)]
### Network Intrusion Detection
#### Offline: DL/ML
- MalMoE: Mixture-of-Experts Enhanced Encrypted Malicious Traffic Detection Under Graph Drift, `arxiv 2026`
- Continual Learning with Strategic Selection and Forgetting for Network Intrusion Detection, `arxiv 2025` [[paper](https://doi.org/10.1109/infocom55648.2025.11044615)]
- Generative Active Adaptation for Drifting and Imbalanced Network Intrusion Detection, `arxiv 2025`
- Hierarchical Local-Global Feature Learning for Few-shot Malicious Traffic Detection, `arxiv 2025`
- Self-Supervised Learning of Graph Representations for Network Intrusion Detection, `arxiv 2025`
- $\mathsf{TCG}\text{-}\mathsf{IDS}$ : Robust Network Intrusion Detection via Temporal Contrastive Graph Learning, `TIFS 2025` [[paper](https://doi.org/10.1109/tifs.2025.3530702)]
- ContraMTD: An Unsupervised Malicious Network Traffic Detection Method based on Contrastive Learning, `WWW 2024` [[paper](https://dl.acm.org/doi/10.1145/3589334.3645479)]
- Delm: Deep Ensemble Learning Model for Anomaly Detection in Malicious Network Traffic-based Adaptive Feature Aggregation and Network Optimization, `TOPS 2024` [[paper](https://doi.org/10.1145/3690637)]
- Detecting Tunneled Flooding Traffic via Deep Semantic Analysis of Packet Length Patterns, `CCS 2024` [[paper](https://doi.org/10.1145/3658644.3670353)]
- Device Identification and Anomaly Detection in IoT Environments, `IOT 2024` [[paper](https://doi.org/10.1109/JIOT.2024.3522863)]
- Divide, Conquer, and Coalesce: Meta Parallel Graph Neural Network for IoT Intrusion Detection at Scale, `WWW 2024` [[paper](https://doi.org/10.1145/3589334.3645457)]
- Enhanced Few-Shot Malware Traffic Classification via Integrating Knowledge Transfer With Neural Architecture Search, `TIFS 2024` [[paper](https://doi.org/10.1109/TIFS.2024.3396624)]
- Foss: Towards Fine-Grained Unknown Class Detection Against the Open-Set Attack Spectrum With Variable Legitimate Traffic, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10638516)]
- K-GetNID: Knowledge-Guided Graphs for Early and Transferable Network Intrusion Detection, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10605850)]
- Mateen: Adaptive Ensemble Learning for Network Anomaly Detection, `RAID 2024` [[paper](https://dl.acm.org/doi/10.1145/3678890.3678901)] [[code](https://github.com/ICL-ml4csec/Mateen/)]
- NetVigil: Robust and Low-Cost Anomaly Detection for East-West Data Center Security, `NSDI 2024` [[paper](https://www.usenix.org/system/files/nsdi24-hsieh.pdf)] [[code](https://github.com/microsoft/Yatesbury)]
- Practical Cyber Attack Detection With Continuous Temporal Graph in Dynamic Network System, `TIFS 2024` [[paper](https://doi.org/10.1109/TIFS.2024.3385321)]
- RFG-HELAD: A Robust Fine-Grained Network Traffic Anomaly Detection Model Based on Heterogeneous Ensemble Learning, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10534080)]
- Relative Frequency-Rank Encoding for Unsupervised Network Anomaly Detection, `ToN 2024` [[paper](https://ieeexplore.ieee.org/document/10517994)]
- Spider: A Semi-Supervised Continual Learning-based Network Intrusion Detection System, `Infocom 2024` [[paper](https://ieeexplore.ieee.org/document/10621428)]
- TMG-GAN: Generative Adversarial Networks-Based Imbalanced Learning for Network Intrusion Detection, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10312801)]
- TrafCL: Robust Encrypted Malicious Traffic Detection via Contrastive Learning, `CIKM 2024` [[paper](https://doi.org/10.1145/3627673.3679839)]
- Trident: A Universal Framework for Fine-Grained and Class-Incremental Unknown Traffic Detection, `WWW 2024` [[paper](https://dl.acm.org/doi/10.1145/3589334.3645407)] [[code](https://github.com/Secbrain/Trident/)]
- 3D-IDS: Doubly Disentangled Dynamic Intrusion Detection, `KDD 2023` [[paper](https://doi.org/10.1145/3580305.3599238)]
- Application of a Dynamic Line Graph Neural Network for Intrusion Detection With Semisupervised Learning, `TIFS 2023` [[paper](https://doi.org/10.1109/tifs.2022.3228493)]
- CPS-GUARD: Intrusion detection for cyber-physical systems and IoT devices using outlier-aware deep autoencoders, `CS 2023` [[paper](https://doi.org/10.1016/j.cose.2023.103210)]
- ERNN: Error-Resilient RNN for Encrypted Traffic Detection towards Network-Induced Phenomena, `TDSC 2023` [[paper](https://doi.org/10.1109/tdsc.2023.3242134)]
- Learning from Limited Heterogeneous Training Data: Meta-Learning for Unsupervised Zero-Day Web Attack Detection across Web Domains, `CCS 2023` [[paper](https://doi.org/10.1145/3576915.3623123)]
- Point Cloud Analysis for ML-Based Malicious Traffic Detection: Reducing Majorities of False Positive Alarms, `CCS 2023` [[paper](https://dl.acm.org/doi/10.1145/3576915.3616631)]
- TS-IDS: Traffic-aware self-supervised learning for IoT Network Intrusion Detection, `KBS 2023` [[paper](https://doi.org/10.1016/j.knosys.2023.110966)]
- Toward Early and Accurate Network Intrusion Detection Using Graph Embedding, `TIFS 2023` [[paper](https://doi.org/10.1109/tifs.2023.3318960)]
- Augmented Memory Replay-based Continual Learning Approaches for Network Intrusion Detection, `NeurIPS 2023` [[paper](https://proceedings.neurips.cc/paper_files/paper/2023/file/3755a02b1035fbadd5f93a022170e46f-Paper-Conference.pdf)]
- Anomal-E: A self-supervised network intrusion detection system based on graph neural networks, `arxiv 2022` [[paper](https://arxiv.org/abs/2207.06819)]
- Encrypted Malware Traffic Detection via Graph-based Network Analysis, `RAID 2022` [[paper](https://dl.acm.org/doi/10.1145/3545948.3545983)]
- Conditional Variational Auto-Encoder and Extreme Value Theory Aided Two-Stage Learning Approach for Intelligent Fine-Grained Known/Unknown Intrusion Detection, `TIFS 2021` [[paper](https://doi.org/10.1109/tifs.2021.3083422)]
- E-GraphSAGE: A Graph Neural Network based Intrusion Detection System for IoT, `arxiv 2021` [[paper](https://doi.org/10.1109/NOMS54207.2022.9789878)] [[code](https://github.com/waimorris/E-GraphSAGE)]
- Enad: An Ensemble Framework for Unsupervised Network Anomaly Detection, `CSR 2021` [[paper](https://doi.org/10.1109/CSR51186.2021.9527982)]
- Graph-based Solutions with Residuals for Intrusion Detection: the Modified E-GraphSAGE and E-ResGAT Algorithms, `arxiv 2021` [[paper](https://arxiv.org/abs/2111.13597)]
- Random Partitioning Forest for Point-Wise and Collective Anomaly Detection - Application to Network Intrusion Detection, `TIFS 2021` [[paper](https://doi.org/10.1109/TIFS.2021.3050605)]
- Unveiling the potential of Graph Neural Networks for robust Intrusion Detection, `arxiv 2021` [[paper](https://arxiv.org/abs/2107.14756)]
- Automating Botnet Detection with Graph Neural Networks, `arxiv 2020` [[paper](https://arxiv.org/abs/2003.06344)]
- Anomaly-Based Intrusion Detection From Network Flow Features Using Variational Autoencoder, `IEEE Access 2020` [[paper](https://doi.org/10.1109/ACCESS.2020.3001350)]
- Improving Attack Detection Performance in NIDS Using GAN, `COMPSAC 2020` [[paper](https://doi.org/10.1109/COMPSAC48688.2020.0-162)]
- Passban IDS: An Intelligent Anomaly-Based Intrusion Detection System for IoT Edge Devices, `ITJ 2020` [[paper](https://doi.org/10.1109/JIOT.2020.2970501)]
- Throwing Darts in the Dark? Detecting Bots with Limited Data using Neural Data Augmentation, `S&P 2020` [[paper](https://ieeexplore.ieee.org/document/9152805)]
- Unsupervised learning approach for network intrusion detection system using autoencoders, `JS 2019` [[paper](https://doi.org/10.1007/s11227-019-02805-w)]
- Detecting HTTP-based application layer DoS attacks on web servers in the presence of sampling, `Computer Networks 2017` [[paper](https://doi.org/10.1016/j.comnet.2017.03.018)]
#### Online: DL/ML (In-Network)
- AOC-IDS: Autonomous Online Framework with Contrastive Learning for Intrusion Detection, `Infocom 2024` [[paper](https://arxiv.org/abs/2402.01807)] [[code](https://github.com/xinchen930/AOC-IDS)]
- Effective DDoS Mitigation via ML-Driven In-Network Traffic Shaping, `TDSC 2024` [[paper](https://doi.org/10.1109/TDSC.2023.3349180)]
- Enhancing Network Attack Detection with Distributed and In-Network Data Collection System, `Security 2024` [[paper](https://www.usenix.org/conference/usenixsecurity24/presentation/mirnajafizadeh)]
- Online Self-Supervised Deep Learning for Intrusion Detection Systems, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10531267)]
- Proteus: A Difficulty-Aware Deep Learning Framework for Real-Time Malicious Traffic Detection, `ICNP 2024` [[paper](https://doi.org/10.1109/ICNP61940.2024.10858520)]
- Rids: Towards Advanced IDS via RNN Model and Programmable Switches Co-Designed Approaches, `Infocom 2024` [[paper](https://ieeexplore.ieee.org/document/10621290)] [[code](https://github.com/Secbrain/RIDS/)]
- Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis, `NDSS 2023` [[paper](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/)] [[code](https://github.com/fuchuanpu/HyperVision)]
- HorusEye: A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches, `Security 2023` [[paper](https://www.usenix.org/conference/usenixsecurity23/presentation/dong-yutao)] [[code](https://github.com/vicTorKd/HorusEye)]
- Real-Time Malicious Traffic Detection With Online Isolation Forest Over SD-WAN, `TIFS 2023` [[paper](https://doi.org/10.1109/tifs.2023.3262121)]
- Realtime Robust Malicious Traffic Detection via Frequency Domain Analysis, `CCS 2021` [[paper](https://doi.org/10.1145/3460120.3484585)]
- Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection, `NDSS 2018` [[paper](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03A-3_Mirsky_paper.pdf)] [[code](https://github.com/ymirsky/Kitsune-py)]
### Robustness
- AN-Net: an Anti-Noise Network for Anonymous Traffic Classification, `WWW 2024` [[paper](https://doi.org/10.1145/3589334.3645691)]
- Cactus: Obfuscating Bidirectional Encrypted TCP Traffic at Client Side, `TIFS 2024` [[paper](https://doi.org/10.1109/TIFS.2024.3442530)]
- Detecting and Mitigating Sampling Bias in Cybersecurity with Unlabeled Data, `Security 2024` [[paper](https://www.usenix.org/conference/usenixsecurity24/presentation/thirumuruganathan)]
- Low-Quality Training Data Only? A Robust Framework for Detecting Encrypted Malicious Network Traffic, `NDSS 2024` [[paper](https://www.ndss-symposium.org/wp-content/uploads/2024/10/ndss2024-81-slides.pdf)] [[code](https://github.com/XXnormal/RAPIER)]
- MCRe: A Unified Framework for Handling Malicious Traffic With Noise Labels Based on Multidimensional Constraint Representation, `TIFS 2024` [[paper](https://doi.org/10.1109/TIFS.2023.3318962)]
- ProGen: Projection-Based Adversarial Attack Generation Against Network Intrusion Detection, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10531273)]
- ReCDA: Concept Drift Adaptation with Representation Enhancement for Network Intrusion Detection, `KDD 2024` [[paper](https://dl.acm.org/doi/10.1145/3637528.3672007)]
- Scrr: Stable Malware Detection under Unknown Deployment Environment Shift by Decoupled Spurious Correlations Filtering, `TDSC 2024` [[paper](https://doi.org/10.1109/tdsc.2024.3369634)]
- Anomaly Detection in the Open World: Normality Shift Detection, Explanation, and Adaptation, `NDSS 2023` [[paper](https://www.ndss-symposium.org/ndss-paper/anomaly-detection-in-the-open-world-normality-shift-detection-explanation-and-adaptation/)] [[code](https://github.com/dongtsi/OWAD)]
- Bars: Local Robustness Certification for Deep Learning based Traffic Analysis Systems, `NDSS 2023` [[paper](https://www.ndss-symposium.org/ndss-paper/bars-local-robustness-certification-for-deep-learning-based-traffic-analysis-systems/)] [[code](https://github.com/KaiWangGitHub/BARS)]
- CADE: Detecting and Explaining Concept Drift Samples for Security Applications, `Security 2021` [[paper](https://www.usenix.org/conference/usenixsecurity21/presentation/yang-limin)] [[code](https://github.com/whyisyoung/CADE)]
- Fare: Enabling Fine-grained Attack Categorization under Low-quality Labeled Data, `NDSS 2021` [[paper](https://www.ndss-symposium.org/ndss-paper/fare-enabling-fine-grained-attack-categorization-under-low-quality-labeled-data/)]
### Explainability
- Building Transparency in Deep Learning-Powered Network Traffic Classification: A Traffic-Explainer Framework, `arxiv 2025` [[paper](https://doi.org/10.1145/3770854.3783939)]
- Genos: General In-Network Unsupervised Intrusion Detection by Rule Extraction, `Infocom 2024` [[paper](https://arxiv.org/abs/2403.19248)]
- IDS-Agent: An LLM Agent for Explainable Intrusion Detection in IoT Networks, `NeurIPS Workshop 2024`
- Rules Refine the Riddle: Global Explanation for Deep Learning-Based Anomaly Detection in Security Applications, `CCS 2024` [[paper](https://doi.org/10.1145/3658644.3670375)]
- Towards Explainable Network Intrusion Detection using Large Language Models, `arxiv 2024` [[paper](https://doi.org/10.1109/bdcat63179.2024.00021)]
- True Attacks, Attack Attempts, or Benign Triggers? An Empirical Measurement of Network Alerts in a Security Operations Center, `Security 2024` [[paper](https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin)]
- Dissect Black Box: Interpreting for Rule-Based Explanations in Unsupervised Anomaly Detection, `NeurIPS 2024` [[paper](http://papers.nips.cc/paper_files/paper/2024/hash/99261adc8a6356b38bcf999bba9a26dc-Abstract-Conference.html)]
- Everybody’s Got ML, Tell Me What Else You Have: Practitioners’ Perception of ML-Based Security Tools and Explanations, `S&P 2023` [[paper](https://doi.org/10.1109/sp46215.2023.10179321)]
- Finer: Enhancing State-of-the-art Classifiers with Feature Attribution to Facilitate Security Analysis, `CCS 2023` [[paper](https://doi.org/10.1145/3576915.3616599)]
- Towards Understanding Alerts raised by Unsupervised Network Intrusion Detection Systems, `RAID 2023` [[paper](https://doi.org/10.1145/3607199.3607247)]
- Interpreting Unsupervised Anomaly Detection in Security via Rule Extraction, `NeurIPS 2023` [[paper](https://doi.org/10.52202/075280-2718)]
- xNIDS: Explaining Deep Learning-based Network Intrusion Detection Systems for Active Intrusion Responses, `Security 2023` [[paper](https://www.usenix.org/conference/usenixsecurity23/presentation/wei-feng)] [[code](https://github.com/CactiLab/code-xNIDS)]
- AI/ML for Network Security: The Emperor has no Clothes, `CCS 2022` [[paper](https://dl.acm.org/doi/10.1145/3548606.3560609)] [[code](https://github.com/TrusteeML/trustee)]
- I $^{2}$ RNN: An Incremental and Interpretable Recurrent Neural Network for Encrypted Traffic Classification, `TDSC 2022` [[paper](https://doi.org/10.1109/tdsc.2023.3245411)]
### Website Fingerprinting
- Contrastive Fingerprinting: A Novel Website Fingerprinting Attack over Few-shot Traces, `WWW 2024` [[paper](https://doi.org/10.1145/3589334.3645575)]
- Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes, `Security 2024` [[paper](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting)]
- Robust Multi-tab Website Fingerprinting Attacks in the Wild, `S&P 2023` [[paper](https://doi.org/10.1109/SP46215.2023.10179464)]
- Transformer-based Model for Multi-tab Website Fingerprinting Attack, `CCS 2023` [[paper](https://doi.org/10.1145/3576915.3623107)]
### Mobile App Fingerprinting
- AppSniffer: Towards Robust Mobile App Fingerprinting Against VPN, `WWW 2023` [[paper](https://dl.acm.org/doi/10.1145/3543507.3583473)] [[code](https://github.com/network-traffic/AppSniffer)]
- FOAP: Fine-Grained Open-World Android App Fingerprinting, `Security 2022` [[paper](https://www.usenix.org/conference/usenixsecurity22/presentation/zhang-jianfeng)]
- FlowPrint: Semi-Supervised Mobile-App Fingerprinting on Encrypted Network Traffic, `NDSS 2020` [[paper](https://www.ndss-symposium.org/ndss-paper/flowprint-semi-supervised-mobile-app-fingerprinting-on-encrypted-network-traffic/)] [[code](https://github.com/Thijsvanede/FlowPrint)]
- Robust Smartphone App Identification via Encrypted Network Traffic Analysis, `TIFS 2018` [[paper](https://ieeexplore.ieee.org/document/8006282)] [[code](https://github.com/vftaylor/appscanner)]
### APT Detection & Provenance Graph IDS
- ORTHRUS: Achieving High Quality of Attribution in Provenance-based Intrusion Detection Systems, `Security 2025` [[paper](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang)] [[code](https://github.com/ubc-provenance/orthrus)]
- Flash: A Comprehensive Approach to Intrusion Detection via Provenance Graph Representation Learning, `S&P 2024` [[paper](https://doi.org/10.1109/sp54263.2024.00139)] [[code](https://github.com/DART-Laboratory/Flash-IDS)]
- Kairos: Practical Intrusion Detection and Investigation using Whole-system Provenance, `S&P 2024` [[paper](https://ieeexplore.ieee.org/document/10646673)] [[code](https://github.com/ubc-provenance/kairos)]
- MAGIC: Detecting Advanced Persistent Threats via Masked Graph Representation Learning, `Security 2024` [[paper](https://www.usenix.org/conference/usenixsecurity24/presentation/jia-zian)] [[code](https://github.com/FDUDSDE/MAGIC)]
- Nodlink: An Online System for Fine-Grained APT Attack Detection and Investigation, `NDSS 2024` [[paper](https://www.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/)] [[code](https://github.com/PKU-ASAL/Simulated-Data)]
- Understanding and Bridging the Gap Between Unsupervised Network Representation Learning and Security Analytics, `S&P 2024` [[paper](https://ieeexplore.ieee.org/document/10646748)]
- Distdet: A Cost-Effective Distributed Cyber Threat Detection System, `Security 2023` [[paper](https://www.usenix.org/conference/usenixsecurity23/presentation/dong-feng)]
- EdgeTorrent: Real-time Temporal Graph Representations for Intrusion Detection, `RAID 2023` [[paper](https://dl.acm.org/doi/10.1145/3607199.3607238)]
- Prographer: An Anomaly Detection System based on Provenance Graph Embedding, `Security 2023` [[paper](https://www.usenix.org/conference/usenixsecurity23/presentation/yang-fan)]
- Euler: Detecting Network Lateral Movement via Scalable Temporal Link Prediction, `NDSS 2022` [[paper](https://doi.org/10.1145/3588771)] [[code](https://github.com/iHeartGraph/Euler)]
- SHADEWATCHER: Recommendation-guided Cyber Threat Analysis using System Audit Records, `S&P 2022` [[paper](https://ieeexplore.ieee.org/document/9833669)] [[code](https://github.com/jun-zeng/ShadeWatcher)]
- THREATRACE: Detecting and Tracing Host-Based Threats in Node Level Through Provenance Graph Learning, `TIFS 2022` [[paper](https://ieeexplore.ieee.org/document/9899459)] [[code](https://github.com/threaTrace-detector/threaTrace)]
- ATLAS: A Sequence-based Learning Approach for Attack Investigation, `Security 2021` [[paper](https://www.usenix.org/conference/usenixsecurity21/presentation/alsaheel)] [[code](https://github.com/purseclab/ATLAS)]
- DeepAID: Interpreting and Improving Deep Learning-based Anomaly Detection in Security Applications, `CCS 2021` [[paper](https://dl.acm.org/doi/10.1145/3460120.3484589)] [[code](https://github.com/dongtsi/DeepAID)]
- Hopper: Modeling and Detecting Lateral Movement, `Security 2021` [[paper](https://www.usenix.org/conference/usenixsecurity21/presentation/ho)]
- Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI, `RAID 2020` [[paper](https://dl.acm.org/doi/10.5555/3454417.3454438)]
- Unicorn: Runtime Provenance-Based Detector for Advanced Persistent Threats, `NDSS 2020` [[paper](https://www.ndss-symposium.org/ndss-paper/unicorn-runtime-provenance-based-detector-for-advanced-persistent-threats/)] [[code](https://github.com/crimson-unicorn)]
### Traffic Analysis under Distribution Shift
- CD-Net: Robust mobile traffic classification against apps updating, `ComSec 2025` [[paper](https://doi.org/10.1016/j.cose.2024.104214)]
- Detection of Unknown Attacks Through Encrypted Traffic: A Gaussian Prototype-Aided Variational Autoencoder Framework, `TIFS 2025` [[paper](https://doi.org/10.1109/TIFS.2025.3612141)]
- FG-SAT: Efficient Flow Graph for Encrypted Traffic Classification Under Environment Shifts, `TIFS 2025` [[paper](https://doi.org/10.1109/TIFS.2025.3571663)]
- Facing Anomalies Head-On: Network Traffic Anomaly Detection via Uncertainty-Inspired Inter-Sample Differences, `WWW 2025` [[paper](https://doi.org/10.1145/3696410.3714621)]
- M3S-UPD: Efficient Multi-Stage Self-Supervised Learning for Fine-Grained Encrypted Traffic Classification with Unknown Pattern Discovery, `arxiv 2025` [[paper](https://arxiv.org/abs/2505.21462)]
- Reliable Open-Set Network Traffic Classification, `TIFS 2025` [[paper](https://doi.org/10.1109/TIFS.2025.3544067)]
- Respond to Change With Constancy: Instruction-Tuning With LLM for Non-I.I.D. Network Traffic Classification, `TIFS 2025` [[paper](https://doi.org/10.1109/TIFS.2025.3574971)]
- Training Robust Classifiers for Classifying Encrypted Traffic under Dynamic Network Conditions, `CCS 2025` [[paper](https://doi.org/10.1145/3719027.3765073)]
- ECNet: Robust Malicious Network Traffic Detection With Multi-View Feature and Confidence Mechanism, `TIFS 2024` [[paper](https://ieeexplore.ieee.org/document/10592040)]
- TrafficLLM: LLMs for improved open-set encrypted traffic analysis, `arxiv 2024` [[paper](https://doi.org/10.1016/j.comnet.2025.111847)] [[code](https://github.com/ZGC-LLM-Safety/TrafficLLM)]
- Extensible Machine Learning for Encrypted Network Traffic Application Labeling via Uncertainty Quantification, `TAI 2023` [[paper](https://doi.org/10.1109/TAI.2023.3244168)]
- Realistic Website Fingerprinting By Augmenting Network Traces, `CCS 2023` [[paper](https://doi.org/10.1145/3576915.3616639)]
- Rosetta: Enabling Robust TLS Encrypted Traffic Classification in Diverse Network Environments with TCP-Aware Traffic Augmentation, `Security 2023` [[paper](https://doi.org/10.1145/3603165.3607437)]
- Zero-relabelling mobile-app identification over drifted encrypted network traffic, `ComNet 2023` [[paper](https://doi.org/10.1016/j.comnet.2023.109728)]
- Distributionally Robust Neural Networks for Group Shifts: On the Importance of Regularization for Worst-Case Generalization, `ICLR 2020` [[paper](https://arxiv.org/abs/1911.08731)]
- Transfer Learning with Dynamic Adversarial Adaptation Network, `ICDM 2019` [[paper](https://doi.org/10.1109/ICDM.2019.00088)]
- Optimized Invariant Representation of Network Traffic for Detecting Unseen Malware Variants, `Security 2016` [[paper](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/bartos)]
### Datasets & Benchmarks
- Exploring QUIC Dynamics: A Large-Scale Dataset for Encrypted Traffic Analysis, `arxiv 2025` [[paper](https://doi.org/10.1109/MeditCom64437.2025.11104435)]
- A Large-Scale Mobile Traffic Dataset For Mobile Application Identification, `computer journal 2024` [[paper](https://doi.org/10.1093/comjnl/bxad076)]
- Bad Design Smells in Benchmark NIDS Datasets, `EuroS&P 2024` [[paper](https://doi.org/10.1109/EuroSP60621.2024.00042)]
- Evaluating Standard Feature Sets Towards Increased Generalisability and Explainability of ML-Based Network Intrusion Detection, `ToN-IoT:BoT-IoT 2022` [[paper](https://doi.org/10.1016/j.bdr.2022.100359)]
- ToN_IoT: The Role of Heterogeneity and the Need for Standardization of Features and Attack Types in IoT Network Intrusion Data Sets, `IOT 2022` [[paper](https://doi.org/10.1109/JIOT.2021.3085194)]
- A Detailed Analysis of the CICIDS2017 Benchmark Dataset for Intrusion Detection, `2021`
- Detection of DoH Tunnels using Time-series Classification of Encrypted Traffic, `DoH 2020` [[paper](https://doi.org/10.1109/DASC-PICom-CBDCom-CyberSciTech49142.2020.00026)]
- Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy, `CICDDoS2019 2019` [[paper](https://doi.org/10.1109/CCST.2019.8888419)]
- Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization, `CICIDS 2018` [[paper](https://doi.org/10.5220/0006639801080116)]
- Characterization of Tor Traffic using Time based Features, `ISCXTor2016 2017` [[paper](https://doi.org/10.5220/0006105602530262)]
- Characterization of Encrypted and VPN Traffic using Time-related Features, `ISCXVPN2016 2016` [[paper](https://doi.org/10.5220/0005740704070414)]

## Datasets
### Encrypted Traffic & Anonymity
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **Darknet 2020** (CICDarknet2020) | 2020 | Detection and characterisation of darknet (Tor + VPN) traffic, supporting early malware monitoring and post-outbreak analysis. | 8 | CSV | — | [link](https://github.com/Marzoug-Nabil/CIC-darknet2020) |
| **Tor-nonTor dataset** (ISCXTor2016) | 2016 | Tor vs non-Tor traffic classification using time-based flow features extracted with ISCXFlowMeter. | 7 (browsing, email, chat, audio, video, FTP, VoIP) | pcap CSV | 22 GB | [link](https://www.unb.ca/cic/datasets/tor.html) |
| **VPN-nonVPN traffic dataset** (ISCXVPN2016) | 2016 | VPN vs non-VPN traffic classification using time-related flow features. | 14 (VoIP, VPN-VoIP, P2P, VPN-P2P, …) | pcap CSV | 28 GB | [link](https://www.unb.ca/cic/datasets/vpn.html) |
| **AppSniffer mobile-app dataset (×4)** | — | Four labelled mobile-app traffic captures released with AppSniffer (WWW '23). | — | — | — | [link](https://github.com/network-traffic/AppSniffer) |
### Intrusion Detection & Attacks
#### DDoS
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **Realistic IDS — DoS and spoofing attack in IoV** (CICIoV2024) | 2024 | Realistic IDS evaluation for in-vehicle (IoV) CAN-bus DoS and spoofing attacks captured on a 2019 Ford vehicle. | 2 (DoS, spoofing) | CSV | 6.3 MB | [link](https://www.unb.ca/cic/datasets/iov-dataset-2024.html) |
| **CICEV2023 / CICDataset_Organized** (CICEV2023 & CICDataset_Organized) | 2023 | Detection of DDoS attacks against electric-vehicle (EV) charging infrastructure under four simulated attack scenarios. | 4 attack scenarios | json | — | [link](https://www.unb.ca/cic/datasets/cicev2023.html) |
| **DDoS evaluation dataset** (CIC-DDoS2019) | 2019 | Benchmark for distributed denial-of-service attack detection algorithms. | 13 | pcap CSV | multi | [link](https://www.unb.ca/cic/datasets/ddos-2019.html) |
| **CIC UNSW-NB15 Augmented Dataset** (CIC-UNSW-NB15) | — | Augmented UNSW-NB15 derivative with new CICFlowMeter features for adversarial NIDS evaluation. | 10 (9 attack types + benign) | CSV | 1.8 GB | [link](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html) |
#### DNS / DoH Tunneling
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **CIC Bell DNS EXF 2021** (CICBellEXFDNS2021) | 2021 | Low-rate covert data exfiltration over DNS tunnels. | 3 (heavy attack, light attack, benign) | pcap CSV | 270.8 MB | [link](https://www.unb.ca/cic/datasets/dns-exf-2021.html) |
| **DNS over HTTPS** (CIRA-CIC-DoHBrw2020) | 2020 | Encrypted DNS-over-HTTPS traffic for covert-channel and tunnel detection. | 3 (benign DoH, malicious DoH, non-DoH) | pcap CSV | — | [link](https://www.unb.ca/cic/datasets/dohbrw-2020.html) |
| **CIC Bell DNS 2021** (CICBellDNS2021) | — | Malicious-domain detection using lexical, DNS-statistical, and third-party features. | 4 (benign, spam, phishing, malware) | CSV | 400K benign / 13,011 malicious samples | [link](https://www.unb.ca/cic/datasets/dns-2021.html) |
#### Botnet
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **ISCX botnet dataset 2014** (ISCX-Bot-2014) | 2014 | Composite botnet detection benchmark mixing benign traffic with multiple botnet families. | 7 (train) / 16 (test) | archive | 5.3 GB train / 8.5 GB test | [link](https://www.unb.ca/cic/datasets/botnet.html) |
#### IDS / IoT
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **Attack vectors in healthcare** (CICIoMT 2024) | 2024 | Security evaluation for Internet-of-Medical-Things devices over Wi-Fi/MQTT and Bluetooth Low Energy. | 5 (DDoS, DoS, Recon, MQTT, spoofing) | pcap CSV | 10 GB | [link](https://www.unb.ca/cic/datasets/iomt-dataset-2024.html) |
| **CIC EV charger attack dataset 2024** (CICEVSE2024) | 2024 | EV-charging-station security: behavioural analysis and binary/multi-class anomaly detection from ~900 hardware performance counters. | multi | CSV | 2.6 GB | [link](https://www.unb.ca/cic/datasets/evse-dataset-2024.html) |
| **A real-time IoT attack benchmark** (CICIoT 2023) | 2023 | Large-scale IoT attack benchmark with 33 attacks across 105 IoT devices. | 7 (DDoS, DoS, Recon, Web, Brute Force, Spoofing, Mirai) | pcap CSV | multi | [link](https://www.unb.ca/cic/datasets/iotdataset-2023.html) |
| **iCloud Private Relay traffic-analysis dataset** | 2023 · UMass | Website-fingerprinting and traffic-correlation experiments against Apple iCloud Private Relay (UMass, ASIACCS '23). | n/a | pcap CSV | 1.8 GB | [link](https://skulddata.cs.umass.edu/traces/network/ipr_asiaccs23.tar.xz) |
| **IoT profiling dataset** (CICIoT 2022) | 2022 | IoT device profiling, behavioural analysis and identification across Power/Idle/Interactive/Scenario/Active/Attack regimes. | 3 device classes (Audio, Camera, Home Automation) | pcap CSV | <5 GB | [link](https://www.unb.ca/cic/datasets/iotdataset-2022.html) |
| **IPS/IDS dataset on AWS** (CSE-CIC-IDS2018) | 2018 | Network-based anomaly IDS evaluation on AWS-hosted infrastructure. | 7 attack classes (Brute Force, Heartbleed, Botnet, DoS, DDoS, Web, Infiltration) | CSV | — | [link](https://www.unb.ca/cic/datasets/ids-2018.html) |
| **Intrusion detection evaluation dataset** (CIC-IDS2017) | 2017 | IDS/IPS evaluation benchmark with diverse attack scenarios. | 8 (FTP/SSH brute force, DoS, Heartbleed, Web, Infiltration, Botnet, DDoS) | pcap CSV | ~51.1 GB | [link](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **CSIC 2010** | 2010 | HTTP web-attack detection benchmark. | — | — | — | [link](https://drive.google.com/drive/folders/1CDjUmDqUid6vZvMuPQxWLTGXpMT2DfZy) |
| **Enriching IoT datasets** (Enriched_IOT_Datasets) | — | Horizontally and vertically enriched combinations of Bot-IoT and TON-IoT for security analytics. | multi | CSV | — | [link](https://www.unb.ca/cic/datasets/enricheddataset.html) |
### Application & Mobile-App Identification
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **CSTNET 2023** | 2023 · CAS / CSTNET | Anonymised institutional Internet traffic from CSTNET (CAS). | — | json | — | [link](https://drive.google.com/drive/folders/1BUo5TMRuXNvTqNYy0RLeHk4l4Q3BuzSk) |
| **CW-100 2018** | 2023 | Encrypted mobile-app classification benchmark (100 apps). | — | json | — | [link](https://drive.google.com/drive/folders/15_bn19jej17RY1hpzovqVgABiZnLrJ0e) |
| **NUDT MobileTraffic Dataset** | 2023 · Network Forensics Research Lab | Anonymised mobile-app traffic with three label levels: 22 categories, 350 apps, 9 brands × 94 phone models. | 22 traffic categories / 350 apps / 9 brands / 94 models | pcap CSV | 293 GB | [link](https://github.com/Abby-ZS/NUDT_MobileTraffic) |
| **Application Based Network Traffic Dataset** | 2021 | Packet captures of 22 commonly used desktop applications (Kaggle). | 22 applications | PCAP | 6.96 GB | [link](https://www.kaggle.com/datasets/applicationdataset/applicationbasednetworktrafficdataset) |
| **CrossNet2021** | 2021 | Cross-network mobile-app classification benchmark used by ProGraph. | — | — | — | [link](https://github.com/SecTeamPolaris/ProGraph) |
| **MaMPF** | 2018 · Chang Liu; Zigang Cao; Gang Xiong; Gaopeng Gou; Siu-Ming Yiu; Longtao He | Encrypted-traffic classification using multi-attribute Markov probability fingerprints over length-block sequences. | — | — | 950,000+ encrypted flows | [link](https://github.com/WSPTTH/MaMPF) |
| **Cross-Platform iOS/Android Apps (Northeastern Recon)** | 2017 · The Northeastern University | Cross-country (China / India / US) mobile-app traffic captured on Nexus 5 (Android 6) and iPhone 5 / 5s (iOS 10). | — | pcap | — | [link](https://recon.meddle.mobi/cross-market.html) |
| **International Privacy Risks of Mobile Apps** | 2017 · Jingjing Ren, Daniel J. Dubois, David Choffnes | Manual five-minute interaction traces for the top 100 iOS and Android apps to study cross-app privacy leakage. | — | pcap | 8 GB | [link](https://recon.meddle.mobi/cross-market.html) |
| **ANDRUBIS** | 2016 · Martina Lindorfer, Matthias Neugschwandtner, Lukas Weichselbaum, Yanick Fratantonio, Victor van der Veen, Christian Platzer | Static + dynamic analysis traces for over 1M Android apps (~40 % malicious). | — | CSV pcap | 1,000,000+ Android apps | [link](https://drive.google.com/drive/folders/1IXa3IJS9zJS4vggpyU7yda8f7jZjz4gB) |
| **USTC TFC 2016** | 2016 · USTC | Encrypted-traffic classification benchmark from USTC. | — | pcap | — | [link](https://drive.google.com/drive/folders/15zB0b4uS5OL5-xLc_uajb_XVLuvwO4ab) |
| **UNIBS-2009** | 2009 · U. Brescia | Edge-router traffic from a U. Brescia campus network covering 20 workstations. | multi | by request | 27 GB raw / 2.7 GB anonymised + payload-stripped | [link](http://netweb.ing.unibs.it/ntw/) |
| **Moore & Zuev hand-labelled flows** | 2005 · Andrew W. Moore, Denis Zuev (Queen Mary, University of London) | Hand-labelled flow dataset (10 application classes) accompanying Moore & Zuev's SIGMETRICS '05 paper, in WEKA format. | — | paid | 5–17 MB (gzip) | [link](https://www.eecs.qmul.ac.uk/~andrewsm/papers/rr-05-13.pdf) |
| **MAWI Working Group Traffic Archive** | 1999-2024 · WIDE Project | Long-running (1999–) backbone Internet trace archive captured via tcpdump on the WIDE backbone, with anonymised IPs. | — | pcap | — | [link](http://www.wide.ad.jp/) |
| **MAWILab** | daily-updated · WIDE Project | Daily-updated network anomaly labels derived from MAWI traces by combining multiple independent detectors with a graph-based scheme. | — | web view + CSV | — | [link](http://www.fukuda-lab.org/mawilab/) |
### Concept Drift
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **APP-53 2023** | 2023 | Mobile-app traffic with 53 classes for concept-drift evaluation. | — | — | — | [link](https://drive.google.com/drive/folders/1ClmdDmbb8RcxtOvZRhJuWtRtnkyNQgzp) |
### Malware Traffic
| Dataset | Year | Description | Classes | Format | Size | Link |
|---|---|---|---|---|---|---|
| **Evasive PDF Mal 2022** (Evasive-PDFMal2022) | 2022 | Evasive malicious-PDF detection benchmark; evasive samples are filtered via K-means over 32 features. | multi | archive | 1.2 GB | [link](https://www.unb.ca/cic/datasets/pdfmal-2022.html) |
| **Malware Memory Analysis** (CIC MalMem 2022) | 2022 | Memory-dump benchmark for detecting obfuscated malware. | multi | CSV | 358 MB | [link](https://www.unb.ca/cic/datasets/malmem-2022.html) |
| **Android Malware** (CIC MalDroid 2020) | 2020 | Five-class Android malware benchmark (Adware, Banking, SMS, Riskware, Benign) with semi-supervised baselines. | 5 (Adware, Banking, SMS, Riskware, Benign) | APK files Capturing-logs CSV files: | 111 GB+ | [link](https://www.unb.ca/cic/datasets/maldroid-2020.html) |
| **CCCS-CIC-AndMal2020 (Android Malware 2020)** | 2020 | Android malware benchmark co-developed with the Canadian Centre for Cyber Security; 200 K malicious + 200 K benign apps. | 14 categories / 191 malware families | CSV | 400 K apps | [link](https://www.unb.ca/cic/datasets/andmal2020.html) |
| **Android Adware and General Malware Dataset** (CIC-AAGM2017) | 2017 | Android adware and general-malware network traffic captured on real devices. | 3 (Adware, General Malware, Benign) | pcap CSV | 9.1 GB | [link](https://www.unb.ca/cic/datasets/android-adware.html) |
| **Android Malware Dataset** (CIC-AndMal2017) | 2017 | Android malware traffic captured on real smartphones to evade emulator detection. | 4 (Adware, Ransomware, Scareware, SMS) | pcap | — | [link](https://www.unb.ca/cic/datasets/andmal2017.html) |

## Tools
### Packet Parsing
| Tool | Type | Language | Description | Link |
|---|---|---|---|---|
| **Wireshark** | GUI | C / C++ | De-facto graphical network-protocol analyser; deep dissection of 3000+ protocols, capture filters (BPF) and display filters, follow-stream view, decryption (TLS, WPA, …), and a rich plug-in ecosystem. | [link](https://www.wireshark.org/) |
| **tshark** | CLI | C / C++ | Command-line companion to Wireshark sharing the same dissector library; ideal for batch processing and scripted feature extraction (e.g. `tshark -r in.pcap -T fields -e ip.src -e tls.handshake.extensions_server_name`). | [link](https://www.wireshark.org/docs/man-pages/tshark.html) |
| **tcpdump** | CLI | C | Veteran libpcap-based capture and inspection tool; lightweight, ubiquitous on UNIX, the canonical source for raw pcap captures. | [link](https://www.tcpdump.org/) |
| **Zeek** | CLI / framework | C++ | Stateful protocol analyser (formerly Bro) that turns live or replayed traffic into structured logs (conn / dns / ssl / http / files). Many academic NIDS datasets ship Zeek-derived features. | [link](https://zeek.org/) |
| **Scapy** | Python library | Python | Programmable packet-manipulation framework — sniff, craft, send, fuzz and dissect arbitrary protocols; widely used for traffic generation in research code. | [link](https://scapy.net/) |
| **PyShark** | Python library | Python | Pythonic wrapper around tshark; exposes the full Wireshark dissector tree as Python objects for scripted field-level analysis. | [link](https://github.com/KimiNewt/pyshark) |
| **dpkt** | Python library | Python | Pure-Python, zero-dependency pcap parser focused on L2–L4 plus common L7 protocols; often 10–50× faster than PyShark for ML feature extraction loops. | [link](https://github.com/kbandla/dpkt) |
| **nFStream** | Python library | Python / C | High-throughput pcap-to-flow streaming with 80+ statistical features and optional nDPI application identification; modern alternative to CICFlowMeter for ML pipelines. | [link](https://github.com/nfstream/nfstream) |
| **flowcontainer** | Python library | Python | Lightweight tshark wrapper that turns a pcap into per-flow records (5-tuple, packet sizes, inter-arrival times, payload bytes, TLS SNI, HTTP host, …) ready for ML feature engineering. | [link](https://github.com/jmhIcoding/flowcontainer) |
### Packet Splitting / Editing
| Tool | Type | Language | Description | Link |
|---|---|---|---|---|
| **SplitCap** | CLI (Windows / .NET) | C# | Splits a pcap into smaller pcaps per flow, host pair, MAC, port, packet count or seconds; widely cited preprocessing baseline. | [link](https://www.netresec.com/?page=SplitCap) |
| **splitpcap** | CLI / Python library | Python | Open-source SplitCap-style tool with extra modes (per-session, per-direction, sampling); cross-platform and embeddable in Python pipelines. | [link](https://github.com/jmhIcoding/splitpcap) |
| **netkit** | CLI | Rust | High-throughput pcap manipulation toolkit (split / merge / extract / stats) written in Rust; targets million-flow corpora where Python tooling becomes a bottleneck. | [link](https://github.com/duskmoon314/netkit) |
| **ShieldGPT pcap_tool** | CLI | C++ | Pcap preprocessing utilities released alongside ShieldGPT — flow splitting, sampling, filtering, anonymisation and dataset packaging for LLM-based traffic analysis. | [link](https://github.com/wangtz19/ShieldGPT/tree/master/pcap_tool) |
| **editcap** | CLI (ships with Wireshark) | C | Pcap surgery swiss-army knife: split by chunk count or seconds, trim time ranges, fix timestamps, change link-layer encapsulation, anonymise MACs, deduplicate, and convert between pcap/pcapng. | [link](https://www.wireshark.org/docs/man-pages/editcap.html) |
| **mergecap** | CLI (ships with Wireshark) | C | Counterpart to editcap: merge multiple pcaps preserving timestamps; concatenate or interleave by capture time. | [link](https://www.wireshark.org/docs/man-pages/mergecap.html) |
| **pcapfix** | CLI | C | Repairs truncated or corrupted pcap and pcapng files; useful when reusing legacy academic captures with broken global / packet headers. | [link](https://github.com/Rup0rt/pcapfix) |
### Flow Feature Extraction
| Tool | Type | Language | Description | Link |
|---|---|---|---|---|
| **CICFlowMeter** | CLI / library | Java | Reference flow-feature extractor used to label every CIC-* dataset (CIC-IDS2017, CIC-DDoS2019, …); the 80-feature schema mirrored by most published NIDS baselines. | [link](https://github.com/ahlashkari/CICFlowMeter) |
| **Argus** | CLI / daemon | C | Long-running bidirectional flow-record generator producing detailed per-flow records (counts, bytes, timing, performance metrics); standard for academic flow analytics for two decades. | [link](https://openargus.org/) |
| **Tranalyzer2** | CLI | C | Modular plug-in-based flow analyzer that emits 700+ features per flow; supports live capture, offline pcap, and IPv6. | [link](https://tranalyzer.com/) |
| **joy** | CLI | C | Cisco-released flow extractor designed for encrypted-traffic analysis: TLS metadata, byte distribution, packet length / inter-arrival sequences, DNS / HTTP enrichment. | [link](https://github.com/cisco/joy) |
### Traffic Replay / Generation
| Tool | Type | Language | Description | Link |
|---|---|---|---|---|
| **tcpreplay** | CLI suite | C | Replay pcaps onto live interfaces at controlled rates with `tcpreplay`, rewrite addresses with `tcprewrite`, and run interactive client/server replay with `tcpliveplay`. The default tool for testbed-based NIDS evaluation. | [link](https://tcpreplay.appneta.com/) |
| **MoonGen** | CLI | Lua / DPDK | Scriptable line-rate (10–100 Gbps) packet generator built on DPDK; the standard reproducible testbed used in NSDI / SIGCOMM dataplane evaluations. | [link](https://github.com/emmericp/MoonGen) |
| **TRex** | CLI / Python API | C++ / Python (DPDK) | Cisco's stateful traffic generator: supports realistic application emulation, multi-million flow scaling, and a Python client for orchestrated experiments. | [link](https://trex-tgn.cisco.com/) |
### Anonymization
| Tool | Type | Language | Description | Link |
|---|---|---|---|---|
| **CryptoPAn** | C library / CLI | C | Prefix-preserving IP-address anonymisation; the de-facto scheme cited in MAWI, CAIDA and most anonymised-trace dataset releases. | [link](https://en.wikipedia.org/wiki/Crypto-PAn) |
| **tcpdpriv** | CLI | C | Older but still-used trace anonymiser with flexible per-field policies (drop / random / prefix-preserving). The original tool used by the WIDE / MAWI archives. | [link](http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html) |
| **PktAnon** | CLI | C++ | Protocol-aware pcap anonymiser from KIT with an XML/YAML profile describing which headers, payloads, MACs and IPs to strip or pseudonymise. | [link](https://www.tm.kit.edu/software/pktanon/) |

## License
[![CC0](https://licensebuttons.net/p/zero/1.0/88x31.png)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, the maintainers have waived all copyright and related rights to this work under [CC0 1.0 Universal](./LICENSE). The list itself is a curation of publicly available paper metadata; copyright on the underlying papers and code repositories belongs to their respective authors.
