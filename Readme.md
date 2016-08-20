Hi, I'm a mountain goat and I'm going to ram your TCP connections, because that's 
a pretty goat thing to do.

<p align="center">
  <img alt="Me doing goat things" src="http://i.imgur.com/lz6AJNs.gif">
</p>

This is a PoC demonstrating techniques exploiting CVE-2016-5696 [Off-Path TCP Exploits: Global Rate Limit Considered Dangerous](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/cao)
by Yue Cao, Zhiyun Qian, Zhongjie Wang, Tuan Dao, Srikanth V. Krishnamurthy, Lisa M. Marvel presented at USENIX 25th Security Symposium.


This is not a complete implementation of the traffic injection attack. Its merely an implementation
up to the inference of the current clients sequence number window. Due to the timing dependend 
nature it may need additional tuning depening on the host to properly function.



**THE SOFTWARE IS FOR EDUCATIONAL AND RESEARCH PURPOSES.
IT MAY CAUSE UNEXPECTED AND UNDESIRABLE BEHAVIOUR TO OCCUR AND MAY DISTRUPT NORMAL OPERATION OF MACHINES AND NETWORK EQUIPMENT.
IT IS THE USERS RESPONSIBILITY TO ENSURE AN EDQUATE ENVIRONMENT THAT DOES NOT AFFECT ANY THIRD PARTY.**

THE SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSE OR IMPLIED WARRANTIES INCLUDING, 
BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
