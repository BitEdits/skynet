#include <petsc.h>
#include <petscts.h>

typedef struct {
  PetscInt  N;          // Number of drones
  Vec       env_data;   // Environmental data
  PetscReal dt;         // Time step
} AppCtx;

PetscErrorCode RHSFunction(TS ts, PetscReal t, Vec X, Vec F, void *ctx) {
  AppCtx        *app = (AppCtx *)ctx;
  PetscScalar   *f;
  const PetscScalar *x, *env;
  PetscInt      i, j, N = app->N;
  PetscReal     repulsion = 0.1, r_min = 1.0; // Reduced repulsion

  VecGetArray(F, &f);
  VecGetArrayRead(X, &x);
  VecGetArrayRead(app->env_data, &env);

  for (i = 0; i < N; i++) {
    f[2*i] = x[2*i + 1]; // dx_i/dt = v_i
    PetscScalar u_i = 0.0; // Skynet/Link32 control
    PetscScalar f_env = env[i];
    PetscScalar f_swarm = 0.0;
    for (j = 0; j < N; j++) {
      if (i != j) {
        PetscReal dist = PetscSqrtReal((x[2*i] - x[2*j])*(x[2*i] - x[2*j]) + 1e-6);
        if (dist < r_min) f_swarm += repulsion * (r_min - dist) / dist;
      }
    }
    f[2*i + 1] = u_i + f_env + f_swarm;
  }

  VecRestoreArray(F, &f);
  VecRestoreArrayRead(X, &x);
  VecRestoreArrayRead(app->env_data, &env);
  return 0;
}

int main(int argc, char **argv) {
  PetscInitialize(&argc, &argv, NULL, NULL);
  AppCtx ctx;
  ctx.N = 160; // Start with small number for testing
  ctx.dt = 0.1; // Larger time step

  Vec X, F;
  VecCreateMPI(PETSC_COMM_WORLD, 2*ctx.N, PETSC_DETERMINE, &X);
  VecDuplicate(X, &F);
  VecDuplicate(X, &ctx.env_data);

  PetscRandom rand;
  PetscRandomCreate(PETSC_COMM_WORLD, &rand);
  PetscRandomSetType(rand, PETSCRAND48);
  PetscScalar *x;
  VecGetArray(X, &x);
  for (PetscInt i = 0; i < ctx.N; i++) {
    PetscReal r;
    PetscRandomGetValue(rand, &r);
    x[2*i] = r * 10.0;
    x[2*i + 1] = 0.0;
  }
  VecRestoreArray(X, &x);
  VecSet(ctx.env_data, 0.1);
  PetscRandomDestroy(&rand);

  TS ts;
  TSCreate(PETSC_COMM_WORLD, &ts);
  TSSetProblemType(ts, TS_NONLINEAR);
  TSSetRHSFunction(ts, NULL, RHSFunction, &ctx);
  TSSetType(ts, TSRK); // Simpler Runge-Kutta
  TSSetTimeStep(ts, ctx.dt);
  TSSetMaxTime(ts, 10.0);
  TSSetSolution(ts, X);
  TSSetFromOptions(ts);

  TSSolve(ts, X);

  PetscViewer viewer;
  PetscViewerASCIIOpen(PETSC_COMM_WORLD, "skynet_ode.txt", &viewer);
  VecView(X, viewer);
  PetscViewerDestroy(&viewer);

  TSDestroy(&ts);
  VecDestroy(&X);
  VecDestroy(&F);
  VecDestroy(&ctx.env_data);
  PetscFinalize();
  return 0;
}

