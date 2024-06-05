# XXX Experimentation

To generate VEX and VAN files from SBOM files contained within the repos_sbom.txt file.

1. Deploy the tool as indicated in the README.MD file of the project. Don't forget to load the vulnerability database with the commandNo te olvides de cargar la base de datos de vulnerabilidades con el comando "seeds/vulndb_seeder.sh" on Linux systems or "seeds/vulndb_seeder.bat" on Windows systems.

2. Run the command ‘python3 experiment.py’.

Note that the first time you run the experimentation, it will be slower as you have to build the dependency graphs at the direct level for the SBOM files.
If you want to load the graphs to avoid that first load you must run the command "seeds/graphdb_seeder.sh" if you are on Linux or "graphdb_seeder.bat" if you are on Windows.

The old_tests folder contains the zips with the VEX and VAN files generated for job XXX.