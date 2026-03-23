#!/bin/bash
mkdir -p ~/aicontrolhackathon/sample_traces

for f in \
  037cd9dd11a43cfcc63a20bb6692f4a9 \
  0b89473570c9e8fad40e08e64c14f350 \
  101e6127c0478cf8fe0742521c52dbd2 \
  147bfe9d1a076a586780894d0dc14557 \
  18500821bde33e55ec64832b780f7978 \
  1dcba28e26f92464c8d76245d3085f17 \
  309124955d5614ddff8ed6522c110925 \
  3a092e28d42b283e9764bf1f914324a2 \
  42e22d2ba7e6e9eab5920e13b1debc39 \
  43a84841a9565b940b1cc0c0b2951632 \
  48bc630b39ce27dfbc419c7549532fe2 \
  54d87f8006c739feb09976c7a0fcc0fd \
  5a46d7187b2f39950d19e36914f4fd40 \
  5be1cd5293bf501e5a729844d736e132 \
  5f4ab0107cb95282b8e915c9e7c02f09 \
  5f64438549f279c150b97a32356c65e0 \
  62a9e32655bb10480fcfd36d990aeb5c \
  68cbb1b82bc9d253d8fb149c48cfaada \
  6c22db92c91c2a63ffc32b30bc10efa2 \
  6cd52ee1ccbffdf0d3963aa034035725 \
  701f41a63fca2f05c530b4312bbc0dc0 \
  70ec8780126a0e08d828476cb9cf7118
do
  cp ~/Downloads/trajectories/${f}.json ~/aicontrolhackathon/sample_traces/
done

echo "Copied 22 traces to ~/aicontrolhackathon/sample_traces/"
ls ~/aicontrolhackathon/sample_traces/ | wc -l
