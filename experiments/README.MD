# XXX Experimentation

To generate VEX and VAN files from SBOM files contained within the repos_sbom.txt file.

1. Deploy the tool as indicated in the README.MD file of the project.

2. Run the command ‘python3 experiment.py’.

Note that the first time you run the experimentation, it will be slower as you have to build the dependency graphs at the direct level for the SBOM files.

The old_tests folder contains the zips with the VEX and VAN files generated for job XXX.