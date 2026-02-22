CXX = g++
SDK = /Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk
CXXFLAGS = -std=c++17 -O2 -Wall -Wno-deprecated-declarations -Wno-macro-redefined \
           -Iinclude -isystem $(SDK)/usr/include/c++/v1 -isysroot $(SDK)
LDFLAGS_PCAP = -lpcap -pthread
LDFLAGS_MT = -pthread

CORE = src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp \
       src/ja3_fingerprint.cpp src/anomaly_detector.cpp src/geoip.cpp src/types.cpp

BUILDDIR = build

.PHONY: all clean

all: $(BUILDDIR)/dpi_engine $(BUILDDIR)/dpi_mt $(BUILDDIR)/dpi_live $(BUILDDIR)/dpi_dashboard

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/dpi_engine: src/main_working.cpp $(CORE) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILDDIR)/dpi_mt: src/dpi_mt.cpp $(CORE) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_MT)

$(BUILDDIR)/dpi_live: src/main_live.cpp src/live_capture.cpp $(CORE) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_PCAP)

$(BUILDDIR)/dpi_dashboard: src/main_dashboard.cpp src/live_capture.cpp src/dashboard_server.cpp $(CORE) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_PCAP)

clean:
	rm -rf $(BUILDDIR)
